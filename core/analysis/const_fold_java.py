"""Bounded compile-time constant folding for the Java value gate.

Answers ONE question for the sanitizer-cut gate: does every reaching
definition of the sink argument assign a compile-time constant? When
it does, the value consumed at the sink cannot carry taint regardless
of any sanitizer — the OWASP-Benchmark-style dead-branch ternary
(``bar = (7 * 18) + num > 200 ? "constant" : tainted``) is the
canonical shape: the condition folds over literal-only reaching
definitions, the constant branch is selected, and the tainted branch
is provably dead.

Soundness posture (refusal-first, mirroring the Java CFG builder):

* The expression grammar is a closed allowlist — integer / string /
  boolean / char / null literals, parentheses, unary ``-`` / ``!``,
  integer ``+ - * / %`` (division and modulo refuse a zero divisor
  rather than guessing), string ``+`` concatenation, comparisons,
  ``== !=``, ``&& ||``, and the ternary (folded only when its
  condition folds to a boolean). Casts, method calls, field and
  array accesses, and every other node type refuse.
* Identifiers resolve through the caller-supplied reaching-defs
  oracle: every reaching definition of the name at that point must
  itself fold, and all of them must fold to the SAME value —
  disagreeing constants refuse (the branch taken is unknown).
* Java locals cannot be aliased (no address-of), so a local whose
  every reaching definition folds is genuinely constant at the use;
  array elements and fields CAN alias, and they refuse structurally:
  an array/field store is not a ``name = expr`` shape this module
  accepts as a definition.
* Recursion is bounded (depth cap, visited set) — cyclic definitions
  refuse.

Integer semantics are Python's, not Java's: values whose magnitude
exceeds 31-bit two's-complement range refuse rather than model
wraparound (a folded comparison near overflow would otherwise be
wrong in exactly the false-suppression direction).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple



_MAX_DEPTH = 8
_INT_MIN = -(2 ** 31)
_INT_MAX = 2 ** 31 - 1

# Sentinel distinguishing "folds to None (null literal)" from "refuses".
_REFUSE = object()


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


class JavaConstIndex:
    """Per-file index of simple definitions: (line, name) → RHS node.

    Only ``type name = expr;`` declarators and ``name = expr``
    assignments within ``line_span`` are indexed — anything else
    (array stores, field stores, compound assignments, ++/--) is
    absent, so lookups on it refuse.
    """

    def __init__(self, source_text: str,
                 line_span: Tuple[int, int]) -> None:
        self._defs: Dict[Tuple[int, str], Any] = {}
        self._compound_writers: Set[str] = set()
        self.ok = False
        parser = _parser()
        if parser is None:
            return
        try:
            tree = parser.parse(source_text.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return
        lo, hi = line_span
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.start_point[0] + 1 > hi or n.end_point[0] + 1 < lo:
                continue
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if (name is not None and name.type == "identifier"
                        and value is not None):
                    self._defs[(n.start_point[0] + 1,
                                name.text.decode())] = value
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                op = n.child_by_field_name("operator")
                if left is not None and left.type == "identifier":
                    lname = left.text.decode()
                    if op is not None and op.type != "=":
                        # +=, -=, ... — a writer this index doesn't
                        # model; every lookup of the name must refuse.
                        self._compound_writers.add(lname)
                    elif right is not None:
                        self._defs[(n.start_point[0] + 1, lname)] = right
            elif n.type == "update_expression":
                for ch in n.children:
                    if ch.type == "identifier":
                        self._compound_writers.add(ch.text.decode())
            stack.extend(n.children)
        self.ok = True

    def rhs_at(self, lineno: int, name: str):
        if name in self._compound_writers:
            return None
        return self._defs.get((lineno, name))


def fold_expr(node, resolve_name) -> Any:
    """Fold a tree-sitter Java expression node to a constant.

    ``resolve_name(name, depth)`` returns the name's constant value or
    ``_REFUSE``. Returns the folded value or ``_REFUSE``.
    """
    return _fold(node, resolve_name, 0)


REFUSE = _REFUSE


def _fold(node, resolve_name, depth: int) -> Any:
    if node is None or depth > _MAX_DEPTH:
        return _REFUSE
    t = node.type
    if t == "parenthesized_expression":
        inner = [c for c in node.children if c.is_named]
        return _fold(inner[0], resolve_name, depth + 1) if len(inner) == 1 else _REFUSE
    if t == "decimal_integer_literal":
        try:
            v = int(node.text.decode())
        except ValueError:
            return _REFUSE
        return v if _INT_MIN <= v <= _INT_MAX else _REFUSE
    if t == "string_literal":
        # Value identity is all the gate compares; escape fidelity is
        # irrelevant as long as it is deterministic.
        return node.text.decode()
    if t in ("true", "false"):
        return t == "true"
    if t == "null_literal":
        return None
    if t == "character_literal":
        return node.text.decode()
    if t == "identifier":
        return resolve_name(node.text.decode(), depth + 1)
    if t == "unary_expression":
        operand = node.child_by_field_name("operand")
        op = node.child_by_field_name("operator")
        val = _fold(operand, resolve_name, depth + 1)
        if val is _REFUSE or op is None:
            return _REFUSE
        text = op.type
        if text == "-" and isinstance(val, int) and not isinstance(val, bool):
            v = -val
            return v if _INT_MIN <= v <= _INT_MAX else _REFUSE
        if text == "!" and isinstance(val, bool):
            return not val
        return _REFUSE
    if t == "binary_expression":
        left = _fold(node.child_by_field_name("left"), resolve_name, depth + 1)
        if left is _REFUSE:
            return _REFUSE
        op_node = node.child_by_field_name("operator")
        op = op_node.type if op_node is not None else ""
        # Short-circuit forms fold on the left operand alone when it
        # decides the result — mirrors Java evaluation order.
        if op == "&&" and left is False:
            return False
        if op == "||" and left is True:
            return True
        right = _fold(node.child_by_field_name("right"), resolve_name, depth + 1)
        if right is _REFUSE:
            return _REFUSE
        return _fold_binop(op, left, right)
    if t == "ternary_expression":
        cond = _fold(node.child_by_field_name("condition"), resolve_name, depth + 1)
        if not isinstance(cond, bool):
            return _REFUSE
        branch = "consequence" if cond else "alternative"
        return _fold(node.child_by_field_name(branch), resolve_name, depth + 1)
    return _REFUSE


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _fold_binop(op: str, left: Any, right: Any) -> Any:
    if op == "+" and isinstance(left, str) and isinstance(right, str):
        return left + right
    if _is_int(left) and _is_int(right):
        if op in ("+", "-", "*"):
            v = {"+": left + right, "-": left - right, "*": left * right}[op]
            return v if _INT_MIN <= v <= _INT_MAX else _REFUSE
        if op in ("/", "%"):
            if right == 0:
                return _REFUSE
            # Java integer division truncates toward zero.
            q = abs(left) // abs(right)
            if (left < 0) != (right < 0):
                q = -q
            if op == "/":
                return q if _INT_MIN <= q <= _INT_MAX else _REFUSE
            return left - q * right
        if op in ("<", "<=", ">", ">="):
            return {"<": left < right, "<=": left <= right,
                    ">": left > right, ">=": left >= right}[op]
    if op in ("==", "!="):
        if type(left) is type(right) or (left is None or right is None):
            return (left == right) if op == "==" else (left != right)
        return _REFUSE
    if op in ("&&", "||") and isinstance(left, bool) and isinstance(right, bool):
        return (left and right) if op == "&&" else (left or right)
    return _REFUSE


def all_definers_constant(
    rd,
    sink,
    sink_arg: str,
    index: JavaConstIndex,
) -> Optional[str]:
    """None when the constancy proof fails; a short reason string when
    every reaching definition of ``sink_arg`` at ``sink`` folds to the
    same compile-time constant (the reason names the value's type, not
    the value — audit records shouldn't quote scanned content).
    """
    if not index.ok:
        return None

    def resolve_at(node, name: str, depth: int,
                   visiting: Set[Tuple[int, str]]) -> Any:
        if depth > _MAX_DEPTH:
            return _REFUSE
        try:
            defs = rd.at(node, name)
        except Exception:  # noqa: BLE001
            return _REFUSE
        if not defs:
            return _REFUSE
        values: List[Any] = []
        for d in defs:
            lineno = getattr(d, "lineno", 0)
            key = (lineno, name)
            if key in visiting:
                return _REFUSE
            rhs = index.rhs_at(lineno, name)
            if rhs is None:
                return _REFUSE
            visiting.add(key)
            val = _fold(
                rhs,
                lambda nm, dp, _d=d: resolve_at(_d, nm, dp, visiting),
                depth,
            )
            visiting.discard(key)
            if val is _REFUSE:
                return _REFUSE
            values.append(val)
        first = values[0]
        for v in values[1:]:
            if v is not first and v != first:
                return _REFUSE
            if type(v) is not type(first):
                return _REFUSE
        return first

    value = resolve_at(sink, sink_arg, 0, set())
    if value is _REFUSE:
        return None
    return (
        f"every reaching definer of the sink argument folds to the "
        f"same compile-time {type(value).__name__} constant"
    )
