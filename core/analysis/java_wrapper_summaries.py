"""Wrapper summaries for the Java value gate — same-class, same-file
cross-class, and depth-2 composition.

The Java analog of :mod:`core.analysis.interproc` (Phase 14, Python):
when the analysed method calls a small helper whose return value is
provably the output of a catalog sanitizer applied to its argument,
synthesise a
:class:`core.dataflow.sanitizer_catalog.SanitizerBinding` at the call
site so the four-condition value gate treats the helper call exactly
like a direct sanitizer call.

Three call forms bind (b19 shipped the first; b21 added the rest):

* bare ``helper(x)`` — a helper of the ENCLOSING class, ``private``
  or ``static`` (no dynamic dispatch);
* static ``Helper.esc(x)`` — a ``static`` method of another class
  declared in the SAME compilation unit;
* instance-creation ``new Helper().m(x)`` — an instance method of a
  same-file class, only under the trivial-construction and
  instance-state rules below. This is the OWASP Benchmark's
  ``new Test().doSomething(request, param)`` shape — measured
  same-file (private inner class) across the corpus.

Cross-class acceptance (all must hold, else a refusal decision):

* the helper class is declared in this compilation unit, its simple
  name is unambiguous in the file, and it is ``private`` or ``final``
  or nested — and NO class in the file ``extends`` it (bounded
  dispatch: nothing in scope can override the summarised method);
* the instance form additionally requires trivial construction — no
  declared constructor, or only zero-parameter constructors whose
  bodies are empty (a constructor parameter could store taint into
  instance state, so ``new Holder(x).out()`` refuses at the call
  site regardless of the constructor's body);
* instance-form bodies obey the STRICT state rule: local
  declarations plus a single trailing return only (no bare
  assignments — an undeclared assignment target could be a field),
  and no ``this`` / ``super`` / field access anywhere in the body.

Depth-2 composition: a helper whose return calls ANOTHER helper binds
only when the inner helper already earned a depth-1 (catalog-only)
summary in the same class — the composition of two proven summaries,
never general interprocedural analysis. Depth 3, recursion, and
two-helper cycles refuse structurally: pass 1 admits catalog-only
returns, pass 2 admits pass-1 callees, and nothing admits a pass-2
callee. An argument position the inner summary IGNORES (its
parameter provably never reaches the inner return — pass 1 refuses
any helper where a parameter reaches the return outside a sanitizer)
is skipped: the value is discarded, so nothing about it needs
proving.

Everything else keeps b19's refusal taxonomy: overload ambiguity,
varargs, non-straight-line bodies, reassigned locals, parameters
reaching the return outside a sanitizer, non-catalog calls (beyond
the composition rule), unknown names, and non-``+`` operators all
refuse; ``this.helper(...)`` produces no CallSite in the builder and
never binds (pinned by test — a builder change must force a
deliberate decision here); a variable receiver (``b.m(x)``) is never
indexed, so dispatch through a receiver whose dynamic type is
unknown can never bind.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    sanitizer_callables_for_cwe,
)

logger = logging.getLogger(__name__)

_MAX_BODY_STATEMENTS = 6
_MAX_SUBST_DEPTH = 4

_IDENT = "identifier"
_METHOD_DECL = "method_declaration"
_CTOR_DECL = "constructor_declaration"
_CLASS_DECL = "class_declaration"
_BLOCK = "block"
_RETURN = "return_statement"
_LOCAL_DECL = "local_variable_declaration"
_EXPR_STMT = "expression_statement"
_ASSIGNMENT = "assignment_expression"
_DECLARATOR = "variable_declarator"
_METHOD_INVOCATION = "method_invocation"
_OBJECT_CREATION = "object_creation_expression"
_BINARY = "binary_expression"
_STRING_LITERALS = frozenset({
    "string_literal", "character_literal", "decimal_integer_literal",
    "hex_integer_literal", "true", "false", "null_literal",
})
_STATE_NODES = frozenset({"this", "super", "field_access"})


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


def _unwrap(n):
    from core.analysis.cfg_builder_java import _unwrap_value_expr
    return _unwrap_value_expr(n)


def _text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


@dataclass(frozen=True)
class WrapperSummary:
    """Summary for one qualifying helper: which parameter positions
    flow to the return exclusively through catalog sanitizers (a
    position missing here provably never reaches the return), and
    through which sanitizer callables. ``bare_callable`` marks
    enclosing-class helpers — the only ones a bare call can reach."""
    owner: str
    simple_name: str
    arity: int
    sanitized_positions: FrozenSet[int]
    sanitizer_callables: FrozenSet[str]
    is_static: bool
    bare_callable: bool


@dataclass
class _CallInfo:
    """One qualifying invocation at the call-site index: receiver
    form ('bare' / 'static' / 'creation' / 'creation_args') plus the
    positional argument identifiers (None for non-identifier args)."""
    form: str
    owner: Optional[str]
    args: Tuple[Optional[str], ...]


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _modifiers(decl) -> Set[str]:
    mods = next((c for c in decl.children if c.type == "modifiers"), None)
    if mods is None:
        return set()
    return {_text(c) for c in mods.children}


def _param_names(decl) -> Optional[Tuple[str, ...]]:
    params = decl.child_by_field_name("parameters")
    if params is None:
        return None
    out: List[str] = []
    for p in params.children:
        if not p.is_named:
            continue
        if p.type == "spread_parameter":
            return None                      # varargs: arity is fluid
        if p.type != "formal_parameter":
            return None
        name_node = p.child_by_field_name("name")
        if name_node is None:
            return None
        out.append(_text(name_node))
    return tuple(out)


def _iter_named(root):
    stack = [root]
    while stack:
        cur = stack.pop()
        yield cur
        for c in cur.children:
            if c.is_named:
                stack.append(c)


def _subtree_touches_state(n) -> bool:
    for cur in _iter_named(n):
        if cur.type in _STATE_NODES:
            return True
    return False


def _straight_line_locals(body, params: Tuple[str, ...],
                          *, strict_state: bool):
    """Return ``(locals_map, return_expr)`` for a straight-line body,
    or raise :class:`_Refused`. ``strict_state`` (cross-class
    instance helpers) forbids bare assignments entirely — an
    undeclared assignment target could be a field."""
    stmts = [c for c in body.children if c.is_named]
    if len(stmts) > _MAX_BODY_STATEMENTS:
        raise _Refused("body exceeds statement cap")
    if not stmts or stmts[-1].type != _RETURN:
        raise _Refused("body does not end in a single return")
    if strict_state and _subtree_touches_state(body):
        raise _Refused("instance state touched in a cross-class helper")
    locals_map: Dict[str, Any] = {}
    assigned: Set[str] = set()
    for stmt in stmts[:-1]:
        if stmt.type == _LOCAL_DECL:
            decls = [c for c in stmt.children if c.type == _DECLARATOR]
            if len(decls) != 1:
                raise _Refused("multi-declarator local")
            name_node = decls[0].child_by_field_name("name")
            value = decls[0].child_by_field_name("value")
            if name_node is None or value is None:
                raise _Refused("local without initializer")
            name = _text(name_node)
            if name in assigned or name in params:
                raise _Refused("local reassignment / parameter shadowing")
            assigned.add(name)
            locals_map[name] = value
            continue
        if stmt.type == _EXPR_STMT:
            if strict_state:
                raise _Refused(
                    "bare assignment in a cross-class helper body")
            inner = next((c for c in stmt.children if c.is_named), None)
            if inner is None or inner.type != _ASSIGNMENT:
                raise _Refused("non-assignment statement in body")
            left = inner.child_by_field_name("left")
            right = inner.child_by_field_name("right")
            op = inner.child_by_field_name("operator")
            if (left is None or left.type != _IDENT or right is None
                    or _text(op) != "="):
                raise _Refused("unsupported assignment shape in body")
            name = _text(left)
            if name in assigned or name in params:
                raise _Refused("local reassignment / parameter shadowing")
            assigned.add(name)
            locals_map[name] = right
            continue
        raise _Refused(f"unsupported body statement: {stmt.type}")
    ret = stmts[-1]
    ret_expr = next((c for c in ret.children if c.is_named), None)
    if ret_expr is None:
        raise _Refused("bare return")
    return locals_map, ret_expr


def _classify_return(
    expr,
    params: Tuple[str, ...],
    locals_map: Dict[str, Any],
    resolver,
    catalog: Set[str],
    composable: Dict[Tuple[str, str, int], "WrapperSummary"],
    owner: str,
) -> Tuple[FrozenSet[int], FrozenSet[str]]:
    """Positions and callables when the return is clean; raises
    :class:`_Refused` otherwise. ``composable`` holds the depth-1
    summaries a bare call may compose with (same owner only)."""
    param_pos = {p: i for i, p in enumerate(params)}
    sanitized: Dict[int, Set[str]] = {}

    def visit(n, inside: Optional[FrozenSet[str]], depth: int) -> None:
        if depth > _MAX_SUBST_DEPTH:
            raise _Refused("substitution depth cap")
        n = _unwrap(n)
        if n is None:
            raise _Refused("unparseable return fragment")
        t = n.type
        if t in _STRING_LITERALS:
            return
        if t == _IDENT:
            name = _text(n)
            if name in param_pos:
                if inside is None:
                    raise _Refused(
                        "parameter reaches return outside a sanitizer")
                sanitized.setdefault(param_pos[name], set()).update(inside)
                return
            if name in locals_map:
                visit(locals_map[name], inside, depth + 1)
                return
            raise _Refused("unknown name in return expression")
        if t == _METHOD_INVOCATION:
            try:
                resolved = resolver.callable_name(n)
            except Exception:  # noqa: BLE001 — resolver over scanned source
                resolved = None
            args = n.child_by_field_name("arguments")
            named_args = [c for c in args.children if c.is_named] \
                if args is not None else []
            if resolved is not None and resolved in catalog:
                for c in named_args:
                    visit(c, frozenset({resolved}), depth + 1)
                return
            # depth-2 composition: bare call to a depth-1 summary of
            # the SAME class.
            if n.child_by_field_name("object") is None:
                key = (owner, _text(n.child_by_field_name("name")),
                       len(named_args))
                summary = composable.get(key)
                if summary is not None:
                    for i, c in enumerate(named_args):
                        if i in summary.sanitized_positions:
                            visit(c, summary.sanitizer_callables,
                                  depth + 1)
                        # else: the inner summary proves position i
                        # never reaches its return — value discarded.
                    return
            raise _Refused("non-catalog call in return expression")
        if t == _BINARY:
            op = n.child_by_field_name("operator")
            if op is None or op.type != "+":
                raise _Refused("non-concatenation operator in return")
            visit(n.child_by_field_name("left"), inside, depth + 1)
            visit(n.child_by_field_name("right"), inside, depth + 1)
            return
        raise _Refused(f"unsupported return construct: {t}")

    visit(expr, None, 0)
    if not sanitized:
        raise _Refused("no parameter flows through a sanitizer")
    positions = frozenset(sanitized)
    callables = frozenset(c for cs in sanitized.values() for c in cs)
    return positions, callables


# ---------------------------------------------------------------------------
# Class inventory
# ---------------------------------------------------------------------------

@dataclass
class _ClassInfo:
    node: Any
    name: str
    modifiers: Set[str]
    is_nested: bool


def _class_inventory(root) -> Tuple[Dict[str, List[_ClassInfo]], Set[str]]:
    """All class declarations by simple name, plus the set of names
    appearing in any ``extends`` clause in the file."""
    by_name: Dict[str, List[_ClassInfo]] = {}
    extended: Set[str] = set()
    for n in _iter_named(root):
        if n.type != _CLASS_DECL:
            continue
        name_node = n.child_by_field_name("name")
        if name_node is None:
            continue
        parent = n.parent
        is_nested = False
        while parent is not None:
            if parent.type == _CLASS_DECL:
                is_nested = True
                break
            parent = parent.parent
        by_name.setdefault(_text(name_node), []).append(_ClassInfo(
            node=n, name=_text(name_node),
            modifiers=_modifiers(n), is_nested=is_nested,
        ))
        superclass = n.child_by_field_name("superclass")
        if superclass is not None:
            for c in _iter_named(superclass):
                if c.type in (_IDENT, "type_identifier"):
                    extended.add(_text(c))
    return by_name, extended


def _trivially_constructible(cls_node) -> bool:
    """No declared constructor, or only zero-parameter constructors
    whose bodies are empty (a lone ``super();`` allowed)."""
    body = cls_node.child_by_field_name("body")
    if body is None:
        return False
    for child in body.children:
        if child.type != _CTOR_DECL:
            continue
        params = _param_names(child)
        if params is None or len(params) != 0:
            return False
        cbody = child.child_by_field_name("body")
        if cbody is None:
            return False
        for s in cbody.children:
            if s.is_named and s.type != "explicit_constructor_invocation":
                return False
    return True


def _methods_of(cls_node) -> Dict[Tuple[str, int], List[Any]]:
    body = cls_node.child_by_field_name("body")
    out: Dict[Tuple[str, int], List[Any]] = {}
    if body is None:
        return out
    for child in body.children:
        if child.type != _METHOD_DECL:
            continue
        name_node = child.child_by_field_name("name")
        params = _param_names(child)
        if name_node is None or params is None:
            continue
        out.setdefault((_text(name_node), len(params)), []).append(child)
    return out


# ---------------------------------------------------------------------------
# Summary derivation
# ---------------------------------------------------------------------------

def _summarize_class(
    info: _ClassInfo,
    *,
    is_enclosing: bool,
    resolver,
    catalog: Set[str],
    decisions: List[str],
) -> Dict[Tuple[str, str, int], WrapperSummary]:
    """Two-pass summaries for one class. Pass 1 admits catalog-only
    returns; pass 2 re-tries pass-1 refusals allowing composition
    with the pass-1 set (depth exactly 2 — cycles and recursion never
    earn a pass-1 summary, so they refuse in both passes)."""
    owner = info.name
    summaries: Dict[Tuple[str, str, int], WrapperSummary] = {}

    def attempt(name, arity, decls, composable) -> Optional[WrapperSummary]:
        if len(decls) > 1:
            decisions.append(
                f"{owner}.{name}/{arity}: refused (overload ambiguity)")
            return None
        decl = decls[0]
        mods = _modifiers(decl)
        strict = not is_enclosing and "static" not in mods
        if is_enclosing and "private" not in mods and "static" not in mods:
            decisions.append(
                f"{owner}.{name}/{arity}: refused "
                "(overridable instance method)")
            return None
        if "abstract" in mods or "native" in mods:
            decisions.append(f"{owner}.{name}/{arity}: refused (no body)")
            return None
        mbody = decl.child_by_field_name("body")
        if mbody is None or mbody.type != _BLOCK:
            decisions.append(
                f"{owner}.{name}/{arity}: refused (no block body)")
            return None
        params = _param_names(decl) or ()
        try:
            locals_map, ret_expr = _straight_line_locals(
                mbody, params, strict_state=strict)
            positions, callables = _classify_return(
                ret_expr, params, locals_map, resolver, catalog,
                composable, owner)
        except _Refused as r:
            decisions.append(
                f"{owner}.{name}/{arity}: refused ({r.reason})")
            return None
        return WrapperSummary(
            owner=owner, simple_name=name, arity=arity,
            sanitized_positions=positions,
            sanitizer_callables=callables,
            is_static="static" in mods,
            bare_callable=is_enclosing,
        )

    methods = _methods_of(info.node)
    pending: List[Tuple[str, int, List[Any]]] = []
    for (name, arity), decls in methods.items():
        s = attempt(name, arity, decls, composable={})
        if s is not None:
            summaries[(owner, name, arity)] = s
            decisions.append(
                f"{owner}.{name}/{arity}: sanitizes positions "
                f"{sorted(s.sanitized_positions)} via "
                f"{sorted(s.sanitizer_callables)}")
        else:
            pending.append((name, arity, decls))
    pass1 = dict(summaries)
    for name, arity, decls in pending:
        s = attempt(name, arity, decls, composable=pass1)
        if s is not None:
            summaries[(owner, name, arity)] = s
            decisions.append(
                f"{owner}.{name}/{arity}: sanitizes positions "
                f"{sorted(s.sanitized_positions)} via "
                f"{sorted(s.sanitizer_callables)} (depth-2)")
    return summaries


def derive_wrapper_summaries(
    source_text: str,
    line_hint: Tuple[int, int],
    cwe: str,
    language: str,
) -> Tuple[Dict[Tuple[str, str, int], WrapperSummary], List[str]]:
    """Summaries for qualifying helpers reachable from the method
    enclosing ``line_hint``: the enclosing class's own private/static
    helpers plus qualifying same-file helper classes. Returns
    ``(summaries, decisions)`` keyed ``(owner, name, arity)``; empty
    on any parse failure or when the CWE has no catalog sanitizers."""
    decisions: List[str] = []
    catalog = sanitizer_callables_for_cwe(cwe, language)
    if not catalog:
        return {}, ["no catalog sanitizers for this cwe/language"]
    parser = _parser()
    if parser is None:
        return {}, ["tree-sitter java unavailable"]
    try:
        from core.analysis.cfg_builder_java import (
            _NameResolver,
            build_import_map,
        )
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — arbitrary scanned source
        return {}, ["parse failure"]
    root = tree.root_node
    types, statics = build_import_map(root)
    resolver = _NameResolver(types, statics)

    by_name, extended = _class_inventory(root)

    lo, hi = min(line_hint), max(line_hint)
    enclosing: Optional[_ClassInfo] = None
    best_span = None
    for infos in by_name.values():
        for info in infos:
            start = info.node.start_point[0] + 1
            end = info.node.end_point[0] + 1
            if start <= lo and hi <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best_span, enclosing = span, info
    if enclosing is None:
        return {}, ["no enclosing class for the finding's lines"]

    summaries: Dict[Tuple[str, str, int], WrapperSummary] = {}
    summaries.update(_summarize_class(
        enclosing, is_enclosing=True, resolver=resolver,
        catalog=catalog, decisions=decisions))

    for name, infos in by_name.items():
        if len(infos) > 1:
            decisions.append(
                f"{name}: refused (ambiguous class name in file)")
            continue
        info = infos[0]
        if info is enclosing:
            continue
        cls_summaries = _summarize_class(
            info, is_enclosing=False, resolver=resolver,
            catalog=catalog, decisions=decisions)
        # Static methods dispatch exactly (``Cls.m`` names the class;
        # subclass statics hide, never override) — always bindable.
        # Instance summaries need MORE: the creation form's receiver
        # type is exact, but belt-and-braces we still require a
        # dispatch-bounded class (private / final / nested, not
        # extended in this file) plus trivial construction.
        bounded = (
            ("private" in info.modifiers
             or "final" in info.modifiers
             or info.is_nested)
            and name not in extended
        )
        if not bounded or not _trivially_constructible(info.node):
            dropped = {k for k, v in cls_summaries.items()
                       if not v.is_static}
            if dropped:
                decisions.append(
                    f"{name}: instance summaries dropped "
                    "(unbounded dispatch or non-trivial construction)")
            cls_summaries = {
                k: v for k, v in cls_summaries.items() if v.is_static
            }
        summaries.update(cls_summaries)

    for d in decisions:
        logger.debug("java wrapper summary: %s", d)
    return summaries, decisions


# ---------------------------------------------------------------------------
# Call-site index + binding synthesis
# ---------------------------------------------------------------------------

def _positional_args(node) -> Tuple[Optional[str], ...]:
    args_node = node.child_by_field_name("arguments")
    args: List[Optional[str]] = []
    if args_node is not None:
        for c in args_node.children:
            if not c.is_named:
                continue
            u = _unwrap(c)
            args.append(
                _text(u) if u is not None and u.type == _IDENT else None)
    return tuple(args)


def _index_calls(
    source_text: str,
    simple_names: Set[str],
    class_names: Set[str],
) -> Dict[Tuple[int, int], _CallInfo]:
    """Qualifying invocations keyed by the invocation node's
    (lineno, col) — the pair :class:`CallSite` carries. Receiver
    forms beyond bare / same-file-static / zero-arg-creation are
    omitted (a variable receiver's dynamic type is unknown and never
    binds); creation WITH arguments is recorded as its own form so
    the binder refuses it explicitly rather than by absence."""
    parser = _parser()
    if parser is None:
        return {}
    try:
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return {}
    out: Dict[Tuple[int, int], _CallInfo] = {}
    for cur in _iter_named(tree.root_node):
        if cur.type != _METHOD_INVOCATION:
            continue
        name_node = cur.child_by_field_name("name")
        if name_node is None or _text(name_node) not in simple_names:
            continue
        key = (cur.start_point[0] + 1, cur.start_point[1])
        obj = cur.child_by_field_name("object")
        if obj is None:
            out[key] = _CallInfo(
                form="bare", owner=None, args=_positional_args(cur))
            continue
        obj_u = _unwrap(obj)
        if obj_u is None:
            continue
        if obj_u.type == _IDENT and _text(obj_u) in class_names:
            out[key] = _CallInfo(
                form="static", owner=_text(obj_u),
                args=_positional_args(cur))
            continue
        if obj_u.type == _OBJECT_CREATION:
            if any(c.type == "class_body" for c in obj_u.children):
                # ``new Helper() { ... }`` declares an anonymous
                # SUBCLASS — dispatch goes to its overrides, not to
                # the summarised class. Never bind.
                continue
            ty = obj_u.child_by_field_name("type")
            ty_text = _text(ty).split("<", 1)[0].strip()
            if ty_text not in class_names:
                continue
            ctor_args = obj_u.child_by_field_name("arguments")
            n_ctor = len([c for c in ctor_args.children if c.is_named]) \
                if ctor_args is not None else 0
            out[key] = _CallInfo(
                form="creation" if n_ctor == 0 else "creation_args",
                owner=ty_text, args=_positional_args(cur))
    return out


def _simple_of(callsite_name: str) -> str:
    """Trailing simple method name of a CallSite name — handles
    ``m``, ``Helper.m``, and ``new Helper().m``."""
    return callsite_name.rsplit(".", 1)[-1]


def synthetic_wrapper_bindings_java(
    cfg,
    source_text: str,
    line_hint: Tuple[int, int],
    cwe: str,
    language: str,
) -> FrozenSet[SanitizerBinding]:
    """Synthetic bindings for qualifying wrapper calls in ``cfg``.
    Empty frozenset on any failure — best-effort, the
    intra-procedural verdict stands."""
    summaries, _decisions = derive_wrapper_summaries(
        source_text, line_hint, cwe, language)
    if not summaries:
        return frozenset()
    simple_names = {name for (_o, name, _a) in summaries}
    class_names = {owner for (owner, _n, _a) in summaries}
    calls = _index_calls(source_text, simple_names, class_names)

    bindings: List[SanitizerBinding] = []
    for node in cfg.nodes():
        for cs in getattr(node, "call_sites", ()) or ():
            info = calls.get((cs.lineno, cs.col_offset))
            if info is None:
                continue
            if info.form == "creation_args":
                # A constructor argument could store taint into the
                # instance — never bind through it.
                continue
            arity = len(info.args)
            method_name = _simple_of(cs.name)
            if info.form == "bare":
                matching = [
                    s for s in summaries.values()
                    if s.bare_callable and s.simple_name == cs.name
                    and s.arity == arity
                ]
                if len(matching) != 1:
                    continue
                summary = matching[0]
            else:
                summary = summaries.get((info.owner, method_name, arity))
                if summary is None:
                    continue
                if info.form == "static" and not summary.is_static:
                    continue
            input_symbols = frozenset(
                info.args[i]
                for i in summary.sanitized_positions
                if i < len(info.args) and info.args[i] is not None
            )
            if not input_symbols:
                continue
            bindings.append(SanitizerBinding(
                node=node,
                callable=(
                    f"wrapper:{summary.owner}.{summary.simple_name}->"
                    + "+".join(sorted(summary.sanitizer_callables))
                ),
                input_symbols=input_symbols,
                output_symbols=cs.assigned_names,
                lineno=cs.lineno,
            ))
    return frozenset(bindings)


__all__ = [
    "WrapperSummary",
    "derive_wrapper_summaries",
    "synthetic_wrapper_bindings_java",
]
