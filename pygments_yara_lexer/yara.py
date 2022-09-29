from pygments.lexer import RegexLexer
from pygments.token import *


class YaraLexer(RegexLexer):
    name = "YARA"
    aliases = ["yara", "yar"]
    filenames = ["*.yar", "*.yara"]

    tokens = {
        "root": [
            (r"//.*$", Comment.Single),
            (r"import", Keyword),
            (r"rule", Keyword),
            (r"(meta:|strings:|condition:)", Keyword),
            (r"(\Wand\W|\Wor\W)", Keyword),
            (r"\$\w+", Name.Variable),
            (r'"', String.Double, "string_text"),
            (r"/", String.Regex, "string_regexp"),
        ],
        "string_text": [(r'[^"]', String.Double), (r'"', String.Double, "#pop")],
        "string_regexp": [(r"[^/]", String.Regex), (r"/", String.Regex, "#pop")],
    }
