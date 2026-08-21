"""Sanitized source view — comments/strings blanked, offsets preserved."""

from __future__ import annotations

from core.audit.source_view import sanitized_view


class TestCFamily:
    def test_line_comment_blanked(self):
        view = sanitized_view("x = 1; // memcpy here\ny = 2;\n", "a.c")
        assert "memcpy" not in view
        assert "x = 1;" in view and "y = 2;" in view

    def test_block_comment_blanked_newlines_kept(self):
        src = "a;\n/* void check_perm(\n   spans lines */\nb;\n"
        view = sanitized_view(src, "a.c")
        assert "check_perm" not in view
        assert view.count("\n") == src.count("\n")
        assert view.splitlines()[3] == "b;"

    def test_string_contents_blanked_delimiters_kept(self):
        view = sanitized_view('call("system( is banned");', "a.c")
        assert "system" not in view
        assert '""' in view.replace(" ", "")

    def test_char_literal_blanked(self):
        view = sanitized_view("if (c == 'x') strcpy(a, b);", "a.c")
        assert "strcpy(a, b)" in view
        assert "'x'" not in view

    def test_escaped_quote_inside_string(self):
        view = sanitized_view(r'p("a\"b popen( c"); q();', "a.c")
        assert "popen" not in view
        assert "q();" in view

    def test_unterminated_string_stops_at_newline(self):
        view = sanitized_view("s = \"oops\nmemcpy(a, b, n);\n", "a.c")
        assert "memcpy(a, b, n);" in view

    def test_backtick_raw_string_for_go(self):
        view = sanitized_view("s := `exec( inside raw`\nrun()\n", "x.go")
        assert "exec" not in view
        assert "run()" in view

    def test_division_is_not_a_comment(self):
        view = sanitized_view("a = b / c; d = e / f;", "a.c")
        assert view == "a = b / c; d = e / f;"


class TestPythonLike:
    def test_hash_comment_blanked(self):
        view = sanitized_view("x = 1  # os.system here\ny = 2\n", "a.py")
        assert "os.system" not in view
        assert "y = 2" in view

    def test_docstring_blanked(self):
        src = 'def f():\n    """calls eval( on input"""\n    return g()\n'
        view = sanitized_view(src, "a.py")
        assert "eval" not in view
        assert "return g()" in view
        assert view.count("\n") == src.count("\n")

    def test_single_quoted_blanked(self):
        view = sanitized_view("cmd = 'subprocess.run( x'\nrun(cmd)\n", "a.py")
        assert "subprocess" not in view
        assert "run(cmd)" in view

    def test_code_survives(self):
        src = "import os\nos.system(cmd)\n"
        assert "os.system(cmd)" in sanitized_view(src, "a.py")


class TestEdgeCases:
    def test_empty_source(self):
        assert sanitized_view("", "a.c") == ""

    def test_unknown_extension_uses_c_family(self):
        view = sanitized_view("x; // memcpy\n", "a.unknown")
        assert "memcpy" not in view
