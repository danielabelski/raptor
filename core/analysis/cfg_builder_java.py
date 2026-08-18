"""Java intra-procedural CFG builder — the Java leg of the sanitizer-cut arc.

Mirrors :mod:`core.analysis.cfg_builder_cpp`'s contract: a
:class:`JavaCFG` satisfying :class:`core.analysis.dominators.Graph`,
with per-statement nodes carrying ``defs`` / ``uses`` /
``call_sites`` / ``may_escape`` so
:func:`core.analysis.sanitizer_cut.evaluate_finding` consumes it with
no language branches.

Soundness posture (the vertex cut's failure direction is MISSING
edges — a real path absent from the model can make the cut look
complete while execution bypasses it):

* Constructs whose control flow the builder cannot faithfully
  enumerate cause the whole build to REFUSE (return ``None``):
  lambdas, method references, anonymous / local classes, and
  ``switch``. The resolver surfaces the refusal as a
  :class:`~core.analysis.finding_resolver.ResolutionFailure`, so the
  finding survives to the LLM — never a silent wrong graph.
* ``try`` / ``catch`` / ``finally`` is modelled with LIBERAL edges:
  every statement in a ``try`` body gets an edge to every catch
  handler's entry (any statement may throw). Extra edges only add
  paths, which can only make suppression harder — conservative.
* Labeled ``break`` / ``continue`` refuse the build (rare, and a
  mis-targeted jump edge is a missing-path hazard); the unlabeled
  forms target the innermost loop like the C builder.

``may_escape`` (alias conservatism, mirroring the C leg's policy —
every Java object access is through a reference, so a field STORE is
the analog of C's ``->`` write):

* ``array_access`` anywhere in the statement (element aliasing);
* a field STORE (``obj.f = …`` / ``this.f = …``) — writes through a
  reference an alias may observe; plain field READS contribute the
  base name as a use and are not an escape (same as C's ``.`` rule);
* ``System.arraycopy`` calls (the bulk-copy analog).

Callable names are emitted FQN-RESOLVED against the file's explicit
imports so the sanitizer catalog can key on fully-qualified names:
``Encode.forHtml(x)`` under ``import org.owasp.encoder.Encode``
surfaces as ``org.owasp.encoder.Encode.forHtml``. Wildcard imports
resolve nothing (conservative — an unresolved name cannot match the
catalog, so it can never suppress). The chained singleton idiom
``ESAPI.encoder().encodeForHTML(x)`` surfaces with an explicit call
marker: ``org.owasp.esapi.ESAPI.encoder().encodeForHTML`` — only that
exact static-chain shape matches; an instance call
``enc.encodeForHTML(x)`` stays unresolved (no type inference, so no
suppression through it).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from core.analysis.cfg_builder import (
    ENTRY_LINENO,
    EXIT_LINENO,
    CallSite,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node / graph types — same contract as CPPCFGNode / CPPCFG
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JavaCFGNode:
    """One node of a Java method's control-flow graph. Field contract
    identical to :class:`core.analysis.cfg_builder_cpp.CPPCFGNode`."""
    kind: str          # "entry" | "exit" | "stmt"
    lineno: int
    label: str
    calls: FrozenSet[str] = frozenset()
    defs: FrozenSet[str] = frozenset()
    uses: FrozenSet[str] = frozenset()
    call_sites: Tuple[CallSite, ...] = ()
    may_escape: bool = False

    def __repr__(self) -> str:                              # pragma: no cover
        return (
            f"JavaCFGNode({self.kind}, L{self.lineno}, "
            f"{self.label!r}, defs={set(self.defs)!r}, "
            f"uses={set(self.uses)!r})"
        )


@dataclass(frozen=True)
class JavaCFG:
    """Concrete Graph for one Java method / constructor."""
    function_name: str
    file_path: str
    language: str
    entry_node: JavaCFGNode
    exit_node: JavaCFGNode
    _nodes: Tuple[JavaCFGNode, ...]
    _adjacency: Dict[JavaCFGNode, Tuple[JavaCFGNode, ...]]
    params: Tuple[str, ...] = ()

    @property
    def entry(self) -> JavaCFGNode:
        return self.entry_node

    def nodes(self) -> Iterable[JavaCFGNode]:
        return self._nodes

    def successors(self, node: JavaCFGNode) -> Iterable[JavaCFGNode]:
        return self._adjacency.get(node, ())


# ---------------------------------------------------------------------------
# Tree-sitter wiring
# ---------------------------------------------------------------------------


def _get_parser():
    """Lazy-load the tree-sitter Java parser; ``None`` when the
    grammar isn't installed (degrade-cleanly, same as the C leg)."""
    try:
        import tree_sitter_java as ts_lang
        from core.inventory.call_graph import _get_ts_parser
        return _get_ts_parser(ts_lang.language)
    except ImportError:
        return None


_METHOD_DECL = "method_declaration"
_CTOR_DECL = "constructor_declaration"
_BLOCK = "block"
_CTOR_BODY = "constructor_body"

_IF = "if_statement"
_WHILE = "while_statement"
_FOR = "for_statement"
_ENHANCED_FOR = "enhanced_for_statement"
_DO = "do_statement"
_RETURN = "return_statement"
_BREAK = "break_statement"
_CONTINUE = "continue_statement"
_THROW = "throw_statement"
_TRY = "try_statement"
_TRY_WITH_RES = "try_with_resources_statement"
_SYNCHRONIZED = "synchronized_statement"
_LABELED = "labeled_statement"

_EXPR_STMT = "expression_statement"
_LOCAL_VAR_DECL = "local_variable_declaration"
_VAR_DECLARATOR = "variable_declarator"
_ASSIGNMENT = "assignment_expression"
_UPDATE = "update_expression"
_METHOD_INVOCATION = "method_invocation"
_OBJECT_CREATION = "object_creation_expression"
_FIELD_ACCESS = "field_access"
_ARRAY_ACCESS = "array_access"
_IDENT = "identifier"
_CAST = "cast_expression"
_PARENS = "parenthesized_expression"

# Constructs the builder REFUSES (soundness: their control/data flow
# can't be faithfully modelled intra-procedurally).
_REFUSED_NODE_TYPES = frozenset({
    "lambda_expression",
    "method_reference",
    "switch_expression",
    "switch_statement",
    "class_declaration",         # local class inside a method body
    "anonymous_class_body",      # older grammar name
})

# Bulk-copy analog: writes through a destination reference the value
# gate can't follow.
_BULK_COPY_CALLS = frozenset({"System.arraycopy"})


# ---------------------------------------------------------------------------
# Import table — FQN resolution for callable names
# ---------------------------------------------------------------------------


def _node_text(n) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def build_import_map(root) -> Tuple[Mapping[str, str], Mapping[str, str]]:
    """Parse the compilation unit's import declarations.

    Returns ``(type_imports, static_imports)``:

    * ``type_imports``:   simple class name → FQN
      (``Encode`` → ``org.owasp.encoder.Encode``)
    * ``static_imports``: simple member name → FQN
      (``forHtml`` → ``org.owasp.encoder.Encode.forHtml``)

    Wildcard imports are skipped — an unresolvable simple name stays
    unresolved and can never match a catalog FQN (conservative).
    """
    types: Dict[str, str] = {}
    statics: Dict[str, str] = {}
    for child in root.children:
        if child.type != "import_declaration":
            continue
        is_static = any(
            (not c.is_named) and _node_text(c) == "static"
            for c in child.children
        )
        has_wildcard = any(c.type == "asterisk" for c in child.children)
        if has_wildcard:
            continue
        scoped = next(
            (c for c in child.children if c.type == "scoped_identifier"),
            None,
        )
        if scoped is None:
            continue
        fqn = _node_text(scoped)
        simple = fqn.rsplit(".", 1)[-1]
        if is_static:
            statics[simple] = fqn
        else:
            types[simple] = fqn
    return types, statics


# ---------------------------------------------------------------------------
# Expression helpers
# ---------------------------------------------------------------------------


def _unwrap_value_expr(n):
    """Strip casts and parens without changing symbol identity."""
    cur = n
    while cur is not None:
        if cur.type == _CAST:
            val = cur.child_by_field_name("value")
            if val is None:
                return cur
            cur = val
            continue
        if cur.type == _PARENS:
            inner = next((c for c in cur.children if c.is_named), None)
            if inner is None:
                return cur
            cur = inner
            continue
        return cur
    return n


def _base_ident(n) -> Optional[str]:
    """Leftmost identifier: ``a.b.c`` → ``a``; ``arr[i]`` → ``arr``."""
    if n is None:
        return None
    if n.type == _IDENT:
        return _node_text(n)
    if n.type == _FIELD_ACCESS:
        return _base_ident(n.child_by_field_name("object"))
    if n.type == _ARRAY_ACCESS:
        return _base_ident(n.child_by_field_name("array"))
    for c in n.children:
        if c.is_named:
            r = _base_ident(c)
            if r is not None:
                return r
    return None


def _dotted_chain(n) -> Optional[str]:
    """Render an identifier / field_access chain as a dotted string.
    ``org.owasp.esapi.ESAPI`` (parsed as nested field_access) →
    ``"org.owasp.esapi.ESAPI"``. Anything else → None."""
    if n is None:
        return None
    if n.type == _IDENT:
        return _node_text(n)
    if n.type == _FIELD_ACCESS:
        obj = _dotted_chain(n.child_by_field_name("object"))
        field = n.child_by_field_name("field")
        if obj is not None and field is not None:
            return f"{obj}.{_node_text(field)}"
    return None


class _NameResolver:
    """FQN-resolves callable names against the file's imports."""

    def __init__(self, type_imports: Mapping[str, str],
                 static_imports: Mapping[str, str]):
        self.types = dict(type_imports)
        self.statics = dict(static_imports)

    def _resolve_chain(self, chain: str) -> str:
        head, _, rest = chain.partition(".")
        fqn = self.types.get(head)
        if fqn is not None:
            return f"{fqn}.{rest}" if rest else fqn
        return chain

    def callable_name(self, invocation) -> Optional[str]:
        """Resolved dotted name for one ``method_invocation`` (or
        ``object_creation_expression`` → ``new <Type>``)."""
        if invocation.type == _OBJECT_CREATION:
            ty = invocation.child_by_field_name("type")
            ty_text = _node_text(ty) if ty is not None else None
            if not ty_text:
                return None
            return "new " + self.types.get(ty_text, ty_text)
        name_node = invocation.child_by_field_name("name")
        if name_node is None:
            return None
        simple = _node_text(name_node)
        obj = invocation.child_by_field_name("object")
        if obj is None:
            # Bare call — resolves only via a static import.
            fqn = self.statics.get(simple)
            return fqn if fqn is not None else simple
        obj = _unwrap_value_expr(obj)
        if obj.type == _METHOD_INVOCATION:
            # Chained call: mark the receiver as a CALL explicitly so
            # only the exact static-chain idiom can match a catalog
            # key (``…ESAPI.encoder().encodeForHTML``).
            inner = self.callable_name(obj)
            if inner is None:
                return None
            return f"{inner}().{simple}"
        chain = _dotted_chain(obj)
        if chain is None:
            return None
        return f"{self._resolve_chain(chain)}.{simple}"


def _arg_surface_names(invocation) -> FrozenSet[str]:
    """Bare-name surface of a call's arguments — identifiers and the
    base of field / array accesses; nested calls, literals, binary
    expressions contribute nothing (same under-count rationale as the
    C leg)."""
    args = invocation.child_by_field_name("arguments")
    if args is None:
        return frozenset()
    names: Set[str] = set()
    for child in args.children:
        if not child.is_named:
            continue
        unwrapped = _unwrap_value_expr(child)
        if unwrapped.type == _IDENT:
            names.add(_node_text(unwrapped))
        elif unwrapped.type in (_FIELD_ACCESS, _ARRAY_ACCESS):
            base = _base_ident(unwrapped)
            if base is not None:
                names.add(base)
    return frozenset(names)


def _walk_uses(n, resolver, *, exclude: Optional[set] = None) -> FrozenSet[str]:
    """Identifiers in load position: callee names are excluded (they
    become call sites), field/array accesses contribute their base."""
    if exclude is None:
        exclude = set()
    out: Set[str] = set()
    stack = [n] if n is not None else []
    while stack:
        cur = stack.pop()
        t = cur.type
        if t in (_METHOD_INVOCATION, _OBJECT_CREATION):
            obj = cur.child_by_field_name("object")
            if obj is not None:
                obj_u = _unwrap_value_expr(obj)
                # A static-class receiver (import-resolved or dotted
                # package chain) is a namespace, not a value use; a
                # plain-variable / chained receiver is a value use.
                if obj_u.type == _IDENT and _node_text(obj_u) not in resolver.types:
                    out.add(_node_text(obj_u))
                elif obj_u.type == _METHOD_INVOCATION:
                    stack.append(obj_u)
            args = cur.child_by_field_name("arguments")
            if args is not None:
                for c in args.children:
                    if c.is_named:
                        stack.append(c)
            continue
        if t == _IDENT:
            key = (cur.start_byte, cur.end_byte)
            if key not in exclude:
                out.add(_node_text(cur))
            continue
        if t == _FIELD_ACCESS:
            base = _base_ident(cur)
            if base is not None and base not in resolver.types:
                out.add(base)
            continue
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    return frozenset(out)


def _walk_call_sites(
    n, resolver, *, assigned_for_root: FrozenSet[str] = frozenset(),
) -> Tuple[CallSite, ...]:
    """Every call in ``n`` as :class:`CallSite`, sorted so
    ``call_sites[-1]`` is the syntactic outermost (end-byte order,
    matching both existing builders)."""
    out: List[Tuple[int, int, CallSite]] = []
    root_id = id(_unwrap_value_expr(n)) if n is not None else None

    def visit(node) -> None:
        if node.type in (_METHOD_INVOCATION, _OBJECT_CREATION):
            name = resolver.callable_name(node)
            is_root = id(node) == root_id or \
                id(_unwrap_value_expr(node)) == root_id
            assigned = assigned_for_root if is_root else frozenset()
            if name is not None:
                out.append((node.end_byte, id(node), CallSite(
                    name=name,
                    arg_names=_arg_surface_names(node),
                    assigned_names=assigned,
                    lineno=node.start_point[0] + 1,
                    col_offset=node.start_point[1],
                )))
            obj = node.child_by_field_name("object")
            if obj is not None and _unwrap_value_expr(obj).type == _METHOD_INVOCATION:
                visit(_unwrap_value_expr(obj))
            args = node.child_by_field_name("arguments")
            if args is not None:
                for c in args.children:
                    if c.is_named:
                        visit(c)
            return
        for c in node.children:
            if c.is_named:
                visit(c)

    if n is not None:
        visit(n)
    out.sort(key=lambda t: (t[0], t[1]))
    return tuple(cs for _, _, cs in out)


def _subtree_may_escape(n, resolver) -> bool:
    """Java escape policy: array_access anywhere; field STORE
    (assignment whose LHS is a field_access); System.arraycopy."""
    if n is None:
        return False
    stack = [n]
    while stack:
        cur = stack.pop()
        t = cur.type
        if t == _ARRAY_ACCESS:
            return True
        if t == _ASSIGNMENT:
            lhs = cur.child_by_field_name("left")
            if lhs is not None and lhs.type == _FIELD_ACCESS:
                return True
        if t == _METHOD_INVOCATION:
            name = resolver.callable_name(cur)
            if name in _BULK_COPY_CALLS:
                return True
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    return False


def _subtree_has_refused(n) -> bool:
    if n is None:
        return False
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type in _REFUSED_NODE_TYPES:
            return True
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    return False


# ---------------------------------------------------------------------------
# Statement payloads
# ---------------------------------------------------------------------------


def _payload_from_local_var_decl(decl, resolver):
    defs: Set[str] = set()
    uses: Set[str] = set()
    calls: Set[str] = set()
    css: List[CallSite] = []
    for child in decl.children:
        if child.type != _VAR_DECLARATOR:
            continue
        name_node = child.child_by_field_name("name")
        tgt = _node_text(name_node) if name_node is not None else None
        if tgt:
            defs.add(tgt)
        val = child.child_by_field_name("value")
        if val is not None:
            assigned = frozenset({tgt}) if tgt else frozenset()
            css.extend(_walk_call_sites(
                val, resolver, assigned_for_root=assigned))
            uses |= _walk_uses(val, resolver)
    calls = {cs.name for cs in css}
    return frozenset(calls), frozenset(defs), frozenset(uses), tuple(css)


def _payload_from_assignment(expr, resolver):
    lhs = expr.child_by_field_name("left")
    rhs = expr.child_by_field_name("right")
    op_node = expr.child_by_field_name("operator")
    op = _node_text(op_node) if op_node is not None else "="
    lhs_name = _base_ident(lhs) if lhs is not None else None
    defs = frozenset({lhs_name}) if lhs_name else frozenset()
    uses: Set[str] = set()
    css: List[CallSite] = []
    if op != "=" and lhs_name:
        uses.add(lhs_name)
    if rhs is not None:
        # Assignment through a field / array LHS is NOT a clean
        # rebinding of the base name — the sanitizer-output identity
        # doesn't transfer. Only a plain-identifier LHS earns
        # assigned_names (may_escape additionally covers the store).
        clean_lhs = lhs is not None and lhs.type == _IDENT and op == "="
        assigned = defs if clean_lhs else frozenset()
        css.extend(_walk_call_sites(rhs, resolver, assigned_for_root=assigned))
        uses |= _walk_uses(rhs, resolver)
    if lhs is not None and lhs.type != _IDENT:
        uses |= _walk_uses(lhs, resolver)
    calls = {cs.name for cs in css}
    return frozenset(calls), defs, frozenset(uses), tuple(css)


def _payload_from_subtree(n, resolver):
    if n is None:
        return frozenset(), frozenset(), frozenset(), ()
    css = _walk_call_sites(n, resolver)
    return (
        frozenset({cs.name for cs in css}),
        frozenset(),
        _walk_uses(n, resolver),
        css,
    )


# ---------------------------------------------------------------------------
# Method discovery
# ---------------------------------------------------------------------------


def _method_name(decl) -> Optional[str]:
    n = decl.child_by_field_name("name")
    return _node_text(n) if n is not None else None


def _method_params(decl) -> Tuple[str, ...]:
    params = decl.child_by_field_name("parameters")
    if params is None:
        return ()
    out: List[str] = []
    for p in params.children:
        if p.type not in ("formal_parameter", "spread_parameter"):
            continue
        name_node = p.child_by_field_name("name")
        if name_node is None:
            # spread_parameter nests its name inside a
            # variable_declarator.
            decl = next(
                (c for c in p.children if c.type == _VAR_DECLARATOR), None)
            if decl is not None:
                name_node = decl.child_by_field_name("name")
        if name_node is not None:
            out.append(_node_text(name_node))
    return tuple(out)


def find_enclosing_method(
    source_text: str, source_line: int, sink_line: int,
) -> Tuple[Optional[str], int]:
    """Smallest method / constructor declaration spanning
    [source_line, sink_line]. Returns ``(name, header_line)`` or
    ``(None, 0)``."""
    parser = _get_parser()
    if parser is None:
        return None, 0
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    lo, hi = min(source_line, sink_line), max(source_line, sink_line)
    best: Optional[Tuple[int, str, int]] = None
    stack = [tree.root_node]
    while stack:
        cur = stack.pop()
        if cur.type in (_METHOD_DECL, _CTOR_DECL):
            start = cur.start_point[0] + 1
            end = cur.end_point[0] + 1
            if start <= lo and hi <= end:
                name = _method_name(cur)
                if name is not None:
                    span = end - start
                    if best is None or span < best[0]:
                        best = (span, name, start)
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    if best is None:
        return None, 0
    return best[1], best[2]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class _RefusedConstruct(Exception):
    """Internal: body contains a construct the builder refuses."""


class _JavaCFGBuilder:
    def __init__(self, function_name: str, file_path: str,
                 resolver: _NameResolver):
        self.function_name = function_name
        self.file_path = file_path
        self.resolver = resolver
        self.entry = JavaCFGNode(
            kind="entry", lineno=ENTRY_LINENO,
            label=f"ENTRY:{function_name}",
        )
        self.exit = JavaCFGNode(
            kind="exit", lineno=EXIT_LINENO,
            label=f"EXIT:{function_name}",
        )
        self._adjacency: Dict[JavaCFGNode, List[JavaCFGNode]] = {}
        self._all_nodes: List[JavaCFGNode] = [self.entry, self.exit]
        self._loop_stack: List[Tuple[JavaCFGNode, JavaCFGNode]] = []
        # Ambient catch entries for liberal try-edge wiring.
        self._catch_entry_stack: List[List[JavaCFGNode]] = []
        self._dedupe_counter = 0

    # ----- plumbing -----

    def _link(self, src, dst) -> None:
        self._adjacency.setdefault(src, []).append(dst)

    def _link_many(self, srcs, dst) -> None:
        for s in srcs:
            self._link(s, dst)

    def _make_node(self, *, lineno, label, calls=frozenset(),
                   defs=frozenset(), uses=frozenset(), call_sites=(),
                   may_escape=False) -> JavaCFGNode:
        node = JavaCFGNode(
            kind="stmt", lineno=lineno, label=label, calls=calls,
            defs=defs, uses=uses, call_sites=call_sites,
            may_escape=may_escape,
        )
        if node in self._adjacency or node in self._all_nodes:
            self._dedupe_counter += 1
            node = JavaCFGNode(
                kind="stmt", lineno=lineno,
                label=f"{label} #{self._dedupe_counter}", calls=calls,
                defs=defs, uses=uses, call_sites=call_sites,
                may_escape=may_escape,
            )
        self._all_nodes.append(node)
        return node

    def _short_label(self, n) -> str:
        text = _node_text(n).split("\n", 1)[0].strip()
        return text[:60] + ("…" if len(text) > 60 else "")

    def _ambient_catch_link(self, node: JavaCFGNode) -> None:
        """Liberal try-edge: any statement inside a try body may
        transfer to each enclosing catch handler."""
        for handlers in self._catch_entry_stack:
            for h in handlers:
                self._link(node, h)

    # ----- statements -----

    def _build_stmts(self, body, incoming):
        if isinstance(body, list):
            stmts = body
        elif body.type in (_BLOCK, _CTOR_BODY):
            stmts = [c for c in body.children if c.is_named]
        else:
            return self._build_stmt(body, incoming)
        cursor = incoming
        for stmt in stmts:
            cursor = self._build_stmt(stmt, cursor)
        return cursor

    def _build_stmt(self, stmt, incoming):
        t = stmt.type
        if t in _REFUSED_NODE_TYPES:
            raise _RefusedConstruct(t)
        if t == _IF:
            return self._build_if(stmt, incoming)
        if t == _WHILE:
            return self._build_while(stmt, incoming)
        if t == _FOR:
            return self._build_for(stmt, incoming)
        if t == _ENHANCED_FOR:
            return self._build_enhanced_for(stmt, incoming)
        if t == _DO:
            return self._build_do(stmt, incoming)
        if t in (_TRY, _TRY_WITH_RES):
            return self._build_try(stmt, incoming)
        if t == _RETURN:
            node = self._straight_node(stmt)
            self._link_many(incoming, node)
            self._ambient_catch_link(node)
            self._link(node, self.exit)
            return []
        if t == _THROW:
            node = self._straight_node(stmt)
            self._link_many(incoming, node)
            self._ambient_catch_link(node)
            self._link(node, self.exit)
            return []
        if t == _BREAK:
            return self._build_break(stmt, incoming)
        if t == _CONTINUE:
            return self._build_continue(stmt, incoming)
        if t == _LABELED:
            # Labeled statements pair with labeled break/continue —
            # refused for soundness (see module docstring).
            raise _RefusedConstruct(_LABELED)
        if t == _SYNCHRONIZED:
            body = stmt.child_by_field_name("body")
            return self._build_stmts(body, incoming) \
                if body is not None else incoming
        if t == _BLOCK:
            return self._build_stmts(stmt, incoming)
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        self._ambient_catch_link(node)
        return [node]

    def _straight_node(self, stmt) -> JavaCFGNode:
        if _subtree_has_refused(stmt):
            raise _RefusedConstruct(stmt.type)
        t = stmt.type
        if t == _LOCAL_VAR_DECL:
            calls, defs, uses, css = _payload_from_local_var_decl(
                stmt, self.resolver)
        elif t == _EXPR_STMT:
            inner = next((c for c in stmt.children if c.is_named), None)
            if inner is not None and inner.type == _ASSIGNMENT:
                calls, defs, uses, css = _payload_from_assignment(
                    inner, self.resolver)
            elif inner is not None and inner.type == _UPDATE:
                tgt = _base_ident(inner)
                defs = frozenset({tgt}) if tgt else frozenset()
                uses = defs
                calls, css = frozenset(), ()
            else:
                calls, defs, uses, css = _payload_from_subtree(
                    inner, self.resolver)
        else:
            calls, defs, uses, css = _payload_from_subtree(
                stmt, self.resolver)
        return self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=self._short_label(stmt),
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(stmt, self.resolver),
        )

    def _cond_node(self, stmt, prefix: str) -> JavaCFGNode:
        cond = stmt.child_by_field_name("condition")
        if _subtree_has_refused(cond):
            raise _RefusedConstruct("condition")
        calls, defs, uses, css = _payload_from_subtree(cond, self.resolver)
        return self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=f"{prefix} {self._short_label(cond)}" if cond is not None
            else prefix,
            calls=calls, defs=defs, uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(cond, self.resolver),
        )

    def _build_if(self, stmt, incoming):
        cond_node = self._cond_node(stmt, "if")
        self._link_many(incoming, cond_node)
        self._ambient_catch_link(cond_node)
        conseq = stmt.child_by_field_name("consequence")
        alt = stmt.child_by_field_name("alternative")
        then_out = self._build_stmts(conseq, [cond_node]) \
            if conseq is not None else [cond_node]
        else_out = self._build_stmts(alt, [cond_node]) \
            if alt is not None else [cond_node]
        return then_out + else_out

    def _build_while(self, stmt, incoming):
        header = self._cond_node(stmt, "while")
        self._link_many(incoming, header)
        self._ambient_catch_link(header)
        after = [header]
        self._loop_stack.append((header, header))
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) \
            if body is not None else []
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        return after

    def _build_do(self, stmt, incoming):
        # ``do body while (cond)`` — a synthetic loop-head node makes
        # the second-iteration back edge representable: incoming →
        # head → body… → cond → head (back edge) and cond → after.
        # Without the head→body path via the back edge, paths where
        # taint flows on iteration ≥2 would be missing from the graph
        # — a missing path is the unsound direction for the cut.
        head = self._make_node(
            lineno=stmt.start_point[0] + 1, label="do",
        )
        self._link_many(incoming, head)
        self._ambient_catch_link(head)
        header = self._cond_node(stmt, "do-while")
        self._loop_stack.append((header, head))
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [head]) \
            if body is not None else [head]
        self._loop_stack.pop()
        self._link_many(body_out, header)
        self._ambient_catch_link(header)
        self._link(header, head)
        return [header]

    def _build_for(self, stmt, incoming):
        init = stmt.child_by_field_name("init")
        cursor = incoming
        if init is not None:
            init_node = self._straight_node(init)
            self._link_many(cursor, init_node)
            self._ambient_catch_link(init_node)
            cursor = [init_node]
        header = self._cond_node(stmt, "for")
        self._link_many(cursor, header)
        self._ambient_catch_link(header)
        update = stmt.child_by_field_name("update")
        self._loop_stack.append((header, header))
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) \
            if body is not None else []
        if update is not None:
            upd_node = self._straight_node(update)
            self._link_many(body_out, upd_node)
            self._link(upd_node, header)
        else:
            for tail in body_out:
                self._link(tail, header)
        self._loop_stack.pop()
        return [header]

    def _build_enhanced_for(self, stmt, incoming):
        # ``for (T i : expr) body`` — header defines the induction
        # variable and uses the iterable.
        name_node = stmt.child_by_field_name("name")
        value = stmt.child_by_field_name("value")
        if _subtree_has_refused(value):
            raise _RefusedConstruct("enhanced_for value")
        var = _node_text(name_node) if name_node is not None else None
        calls, _d, uses, css = _payload_from_subtree(value, self.resolver)
        header = self._make_node(
            lineno=stmt.start_point[0] + 1,
            label=f"for {var} : {self._short_label(value)}",
            calls=calls,
            defs=frozenset({var}) if var else frozenset(),
            uses=uses, call_sites=css,
            may_escape=_subtree_may_escape(value, self.resolver),
        )
        self._link_many(incoming, header)
        self._ambient_catch_link(header)
        self._loop_stack.append((header, header))
        body = stmt.child_by_field_name("body")
        body_out = self._build_stmts(body, [header]) \
            if body is not None else []
        for tail in body_out:
            self._link(tail, header)
        self._loop_stack.pop()
        return [header]

    def _build_try(self, stmt, incoming):
        catches = [c for c in stmt.children if c.type == "catch_clause"]
        finally_clause = next(
            (c for c in stmt.children if c.type == "finally_clause"), None)
        # Catch entry nodes first, so try-body statements can link.
        catch_entries: List[JavaCFGNode] = []
        for cl in catches:
            param = next(
                (c for c in cl.children if c.type == "catch_formal_parameter"),
                None,
            )
            exc_name = None
            if param is not None:
                idents = [c for c in param.children if c.type == _IDENT]
                exc_name = _node_text(idents[-1]) if idents else None
            entry = self._make_node(
                lineno=cl.start_point[0] + 1,
                label=f"catch {self._short_label(param)}",
                defs=frozenset({exc_name}) if exc_name else frozenset(),
            )
            catch_entries.append(entry)

        # Resources (try-with-resources) are declarations preceding
        # the body.
        cursor = incoming
        resources = next(
            (c for c in stmt.children if c.type == "resource_specification"),
            None,
        )
        if resources is not None:
            for res in resources.children:
                if res.type == "resource":
                    node = self._straight_node(res)
                    self._link_many(cursor, node)
                    for h in catch_entries:
                        self._link(node, h)
                    cursor = [node]

        body = stmt.child_by_field_name("body")
        self._catch_entry_stack.append(catch_entries)
        # Incoming may ALSO reach a catch (the first body statement
        # throws before executing) — liberal edge from each incoming.
        for src in cursor:
            for h in catch_entries:
                self._link(src, h)
        body_out = self._build_stmts(body, cursor) \
            if body is not None else cursor
        self._catch_entry_stack.pop()

        # Catch bodies.
        catch_outs: List[JavaCFGNode] = []
        for cl, entry in zip(catches, catch_entries):
            cbody = cl.child_by_field_name("body")
            outs = self._build_stmts(cbody, [entry]) \
                if cbody is not None else [entry]
            catch_outs.extend(outs)

        join = body_out + catch_outs
        if finally_clause is not None:
            fbody = next(
                (c for c in finally_clause.children if c.type == _BLOCK),
                None,
            )
            if fbody is not None:
                join = self._build_stmts(fbody, join)
        return join

    def _build_break(self, stmt, incoming):
        if any(c.type == _IDENT for c in stmt.children):
            raise _RefusedConstruct("labeled break")
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        if not self._loop_stack:
            self._link(node, self.exit)
            return []
        # break exits the innermost loop: successors resolved by the
        # loop's after-set — the header IS the after-node in this
        # model, but break must NOT re-test the condition. Link to
        # header anyway: extra edge = extra path = conservative.
        self._link(node, self._loop_stack[-1][0])
        return []

    def _build_continue(self, stmt, incoming):
        if any(c.type == _IDENT for c in stmt.children):
            raise _RefusedConstruct("labeled continue")
        node = self._straight_node(stmt)
        self._link_many(incoming, node)
        if not self._loop_stack:
            self._link(node, self.exit)
            return []
        self._link(node, self._loop_stack[-1][1])
        return []


def build_java_intraproc_cfg(
    source_text: str,
    function_name: str,
    *,
    line_hint: Optional[Tuple[int, int]] = None,
) -> Optional[JavaCFG]:
    """Build the CFG for one Java method / constructor.

    ``line_hint`` — when given, the declaration selected is the
    smallest one with the matching name that SPANS the hint range;
    Java overloads share a name, so name-only selection could pick
    the wrong body. Falls back to the first name match when no
    spanning declaration exists.

    Returns ``None`` when the grammar is missing, the method isn't
    found, or the body contains a refused construct (lambdas, method
    references, anonymous/local classes, switch, labeled jumps) —
    the caller treats ``None`` as resolution failure, never as an
    empty-but-valid graph.
    """
    parser = _get_parser()
    if parser is None:
        return None
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    root = tree.root_node

    candidates = []
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur.type in (_METHOD_DECL, _CTOR_DECL) \
                and _method_name(cur) == function_name:
            candidates.append(cur)
        for c in cur.children:
            if c.is_named:
                stack.append(c)
    if not candidates:
        return None
    decl = None
    if line_hint is not None:
        lo, hi = min(line_hint), max(line_hint)
        spanning = [
            d for d in candidates
            if d.start_point[0] + 1 <= lo and hi <= d.end_point[0] + 1
        ]
        if spanning:
            spanning.sort(key=lambda d: d.end_point[0] - d.start_point[0])
            decl = spanning[0]
    if decl is None:
        candidates.sort(key=lambda d: d.start_point[0])
        decl = candidates[0]

    body = decl.child_by_field_name("body")
    if body is None:
        return None

    type_imports, static_imports = build_import_map(root)
    resolver = _NameResolver(type_imports, static_imports)
    builder = _JavaCFGBuilder(function_name, "<memory>", resolver)
    try:
        tails = builder._build_stmts(body, [builder.entry])
    except _RefusedConstruct as rc:
        logger.debug(
            "java CFG refused for %s: unsupported construct %s",
            function_name, rc,
        )
        return None
    builder._link_many(tails, builder.exit)

    adjacency = {
        n: tuple(dsts) for n, dsts in builder._adjacency.items()
    }
    return JavaCFG(
        function_name=function_name,
        file_path="<memory>",
        language="java",
        entry_node=builder.entry,
        exit_node=builder.exit,
        _nodes=tuple(builder._all_nodes),
        _adjacency=adjacency,
        params=_method_params(decl),
    )


__all__ = [
    "JavaCFG",
    "JavaCFGNode",
    "build_java_intraproc_cfg",
    "build_import_map",
    "find_enclosing_method",
]
