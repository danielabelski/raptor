"""One-level same-file wrapper summaries for the Java value gate.

The Java analog of :mod:`core.analysis.interproc` (Phase 14, Python):
when the analysed method calls a small helper defined in the SAME
class whose return value is provably the output of a catalog
sanitizer applied to its argument, synthesise a
:class:`core.dataflow.sanitizer_catalog.SanitizerBinding` at the call
site so the four-condition value gate treats the helper call exactly
like a direct sanitizer call. The OWASP Benchmark's ``doSomething``
wrappers are the measured target (b17 telemetry: helper-wrapped flows
land in ``candidate_only``).

Soundness posture — a binding is synthesised only when EVERY one of
these holds; anything else records a refusal decision and produces
nothing:

* the helper is declared in the same class as the analysed method and
  is ``private`` or ``static`` (no dynamic dispatch — an overridable
  instance method could resolve to anything at runtime);
* exactly one declaration exists for its (name, arity) in that class
  (overload ambiguity refuses);
* the body is straight-line — local declarations / simple
  assignments then a single trailing ``return`` — with at most
  ``_MAX_BODY_STATEMENTS`` statements; branches, loops, try, and
  every construct the CFG builder refuses, refuse here too;
* locals feeding the return are single-assignment (a reassigned local
  refuses — the substitution would be ambiguous);
* the return expression, after bounded local substitution, is built
  ONLY from literals, catalog-sanitizer calls, and string ``+``
  concatenation; a parameter may appear ONLY inside a
  catalog-sanitizer call's arguments. A parameter reaching the return
  outside a sanitizer (directly, through ``+``, through an
  unrecognised call, field, ternary, or anything else) marks the
  helper dirty — no bindings for ANY position (the same symbol could
  be passed at two positions, one clean and one dirty);
* helper depth is exactly one: a call to anything that is not a
  catalog sanitizer — including another same-file helper or the
  helper itself (recursion) — refuses.

Callee matching at the call site is deliberately narrow: only the
bare ``helper(...)`` form binds. ``this.helper(...)`` produces no
CallSite at all in the b13 builder (the ``this`` receiver is not an
identifier node), a name that import-resolution rewrote to an FQN
(static import) never matches, and a qualified ``Other.helper`` call
never matches — cross-class same-file helpers are out of scope
(documented, conservative).

Every accept/refuse decision is returned in ``decisions`` (and logged
at debug) so the postpass refusal telemetry can carry it.
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
_CLASS_DECL = "class_declaration"
_BLOCK = "block"
_RETURN = "return_statement"
_LOCAL_DECL = "local_variable_declaration"
_EXPR_STMT = "expression_statement"
_ASSIGNMENT = "assignment_expression"
_DECLARATOR = "variable_declarator"
_METHOD_INVOCATION = "method_invocation"
_BINARY = "binary_expression"
_STRING_LITERALS = frozenset({
    "string_literal", "character_literal", "decimal_integer_literal",
    "hex_integer_literal", "true", "false", "null_literal",
})


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
    flow to the return exclusively through catalog sanitizers, and
    through which sanitizer callables."""
    simple_name: str
    arity: int
    sanitized_positions: FrozenSet[int]
    sanitizer_callables: FrozenSet[str]


@dataclass
class _CallInfo:
    """Positional argument identifiers of one call node (None for a
    non-identifier argument)."""
    args: Tuple[Optional[str], ...]


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _method_modifiers(decl) -> Set[str]:
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


def _straight_line_locals(body, params: Tuple[str, ...]):
    """Return ``(locals_map, return_expr)`` for a straight-line body,
    or raise :class:`_Refused`."""
    stmts = [c for c in body.children if c.is_named]
    if len(stmts) > _MAX_BODY_STATEMENTS:
        raise _Refused("body exceeds statement cap")
    if not stmts or stmts[-1].type != _RETURN:
        raise _Refused("body does not end in a single return")
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
) -> Tuple[FrozenSet[int], FrozenSet[str]]:
    """Positions and callables when the return is clean; raises
    :class:`_Refused` otherwise."""
    param_pos = {p: i for i, p in enumerate(params)}
    sanitized: Dict[int, Set[str]] = {}

    def visit(n, inside: Optional[str], depth: int) -> None:
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
                sanitized.setdefault(param_pos[name], set()).add(inside)
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
            if resolved is None or resolved not in catalog:
                raise _Refused("non-catalog call in return expression")
            args = n.child_by_field_name("arguments")
            if args is not None:
                for c in args.children:
                    if c.is_named:
                        visit(c, resolved, depth + 1)
            return
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


def derive_wrapper_summaries(
    source_text: str,
    line_hint: Tuple[int, int],
    cwe: str,
    language: str,
) -> Tuple[Dict[Tuple[str, int], WrapperSummary], List[str]]:
    """Summaries for qualifying helpers in the class enclosing
    ``line_hint``. Returns ``(summaries, decisions)``; empty on any
    parse failure or when the CWE has no catalog sanitizers."""
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

    lo, hi = min(line_hint), max(line_hint)
    enclosing_class = None
    best_span = None
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur.type == _CLASS_DECL:
            start, end = cur.start_point[0] + 1, cur.end_point[0] + 1
            if start <= lo and hi <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best_span, enclosing_class = span, cur
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    if enclosing_class is None:
        return {}, ["no enclosing class for the finding's lines"]
    body = enclosing_class.child_by_field_name("body")
    if body is None:
        return {}, ["classless body"]

    # Direct children only — helpers in nested classes don't resolve
    # from a bare call in the outer class's methods.
    by_key: Dict[Tuple[str, int], List[Any]] = {}
    for child in body.children:
        if child.type != _METHOD_DECL:
            continue
        name_node = child.child_by_field_name("name")
        params = _param_names(child)
        if name_node is None or params is None:
            continue
        by_key.setdefault((_text(name_node), len(params)), []).append(child)

    summaries: Dict[Tuple[str, int], WrapperSummary] = {}
    for (name, arity), decls in by_key.items():
        if len(decls) > 1:
            decisions.append(f"{name}/{arity}: refused (overload ambiguity)")
            continue
        decl = decls[0]
        mods = _method_modifiers(decl)
        if "private" not in mods and "static" not in mods:
            decisions.append(
                f"{name}/{arity}: refused (overridable instance method)")
            continue
        if "abstract" in mods or "native" in mods:
            decisions.append(f"{name}/{arity}: refused (no body)")
            continue
        mbody = decl.child_by_field_name("body")
        if mbody is None or mbody.type != _BLOCK:
            decisions.append(f"{name}/{arity}: refused (no block body)")
            continue
        params = _param_names(decl) or ()
        try:
            locals_map, ret_expr = _straight_line_locals(mbody, params)
            positions, callables = _classify_return(
                ret_expr, params, locals_map, resolver, catalog)
        except _Refused as r:
            decisions.append(f"{name}/{arity}: refused ({r.reason})")
            continue
        summaries[(name, arity)] = WrapperSummary(
            simple_name=name, arity=arity,
            sanitized_positions=positions,
            sanitizer_callables=callables,
        )
        decisions.append(
            f"{name}/{arity}: sanitizes positions "
            f"{sorted(positions)} via {sorted(callables)}")
    for d in decisions:
        logger.debug("java wrapper summary: %s", d)
    return summaries, decisions


def _index_calls(
    source_text: str, simple_names: Set[str],
) -> Dict[Tuple[int, int], _CallInfo]:
    """Positional argument identifiers for every invocation whose
    name-field text is in ``simple_names``, keyed by the invocation's
    (lineno, col) — the pair :class:`CallSite` carries."""
    parser = _parser()
    if parser is None:
        return {}
    try:
        tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return {}
    out: Dict[Tuple[int, int], _CallInfo] = {}
    stack = [tree.root_node]
    while stack:
        cur = stack.pop()
        if cur.type == _METHOD_INVOCATION:
            name_node = cur.child_by_field_name("name")
            if name_node is not None and _text(name_node) in simple_names:
                args_node = cur.child_by_field_name("arguments")
                args: List[Optional[str]] = []
                if args_node is not None:
                    for c in args_node.children:
                        if not c.is_named:
                            continue
                        u = _unwrap(c)
                        args.append(
                            _text(u) if u is not None and u.type == _IDENT
                            else None)
                out[(cur.start_point[0] + 1, cur.start_point[1])] = (
                    _CallInfo(args=tuple(args)))
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    return out


def synthetic_wrapper_bindings_java(
    cfg,
    source_text: str,
    line_hint: Tuple[int, int],
    cwe: str,
    language: str,
) -> FrozenSet[SanitizerBinding]:
    """Synthetic bindings for qualifying same-class wrapper calls in
    ``cfg``. Empty frozenset on any failure — best-effort, the
    intra-procedural verdict stands."""
    summaries, _decisions = derive_wrapper_summaries(
        source_text, line_hint, cwe, language)
    if not summaries:
        return frozenset()
    simple_names = {name for (name, _a) in summaries}
    calls = _index_calls(source_text, simple_names)
    bindings: List[SanitizerBinding] = []
    for node in cfg.nodes():
        for cs in getattr(node, "call_sites", ()) or ():
            if cs.name not in simple_names:
                continue
            simple = cs.name
            info = calls.get((cs.lineno, cs.col_offset))
            if info is None:
                continue
            summary = summaries.get((simple, len(info.args)))
            if summary is None:
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
                    f"wrapper:{simple}->"
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
