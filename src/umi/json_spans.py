"""Locate JSON value spans without allocating their decoded graph.

This is a lexical splitter, never an accepting JSON parser. Pydantic validates
all extracted values and the retained framing. Unusual or malformed framing
falls back to the unchanged parser, including its recursion-limit semantics.
"""

import re


class UnsplitJSON(ValueError):
    """Use the complete original JSON parser for this input."""


_STRUCTURE = re.compile(rb'["{}\[\]]')
_PRIMITIVE_END = re.compile(rb"[,}\]\x20\t\r\n]")
_SPACE = b" \t\r\n"


def whitespace(raw: bytes, position: int) -> int:
    while position < len(raw) and raw[position] in _SPACE:
        position += 1
    return position


def string_end(raw: bytes, start: int) -> int:
    if start >= len(raw) or raw[start] != 34:
        raise UnsplitJSON
    position = start + 1
    while True:
        end = raw.find(b'"', position)
        if end < 0:
            raise UnsplitJSON
        slash = end - 1
        while slash >= start and raw[slash] == 92:
            slash -= 1
        if (end - slash - 1) % 2 == 0:
            return end + 1
        position = end + 1


def value_end(raw: bytes, start: int, depth: int) -> int:
    start = whitespace(raw, start)
    if start >= len(raw):
        raise UnsplitJSON
    first = raw[start]
    if first == 34:
        return string_end(raw, start)
    if first not in (91, 123):
        match = _PRIMITIVE_END.search(raw, start)
        end = len(raw) if match is None else match.start()
        if end == start:
            raise UnsplitJSON
        return end
    stack = [93 if first == 91 else 125]
    position = start + 1
    while stack:
        if depth + len(stack) > 128:
            # Stay below the native parser's recursion boundary. Near that
            # boundary, use the original whole-document parser unchanged.
            raise UnsplitJSON
        match = _STRUCTURE.search(raw, position)
        if match is None:
            raise UnsplitJSON
        token = raw[match.start()]
        position = match.end()
        if token == 34:
            position = string_end(raw, match.start())
        elif token in (91, 123):
            stack.append(93 if token == 91 else 125)
        elif token != stack.pop():
            raise UnsplitJSON
    return position
