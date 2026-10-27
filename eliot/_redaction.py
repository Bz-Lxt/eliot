"""
Support for redacting sensitive values from log messages.

Sensitive values can be declared in two ways:

1. On a L{eliot.Field} definition, by passing C{sensitive=True}. Every
   message serialized with that field will have the field's value redacted.

2. Globally, via L{eliot.add_sensitive_fields}, which takes field names
   (matched recursively at every level of nested messages) or rooted field
   paths (sequences of field names).

Redaction is applied to a copy of the message before it is serialized or
delivered to any destination (and therefore before any failure diagnostic
message that embeds the message is generated). The originally logged object,
non-sensitive fields, and Eliot's causal metadata are never modified.
"""

from threading import Lock

# The placeholder substituted for sensitive values.
REDACTED = "[REDACTED]"


def _as_path(path):
    """
    Normalize a user-provided sensitive field specification to a tuple of
    field names.

    A bare C{str} is treated as a single-field path, a L{eliot.Field} as a
    path containing just its key, and any other iterable as a sequence of
    C{str} field names.
    """
    if isinstance(path, str):
        return (path,)
    key = getattr(path, "key", None)
    if isinstance(key, str):
        return (key,)
    key_path = tuple(path)
    if not key_path or not all(isinstance(key, str) for key in key_path):
        raise TypeError(
            "Sensitive fields must be specified as a str, a Field, or a "
            "non-empty sequence of str, got: %r" % (path,)
        )
    return key_path


class SensitiveFields(object):
    """
    Global registry of sensitive field names and rooted field paths.

    @cvar _names: Field names whose values are sensitive wherever they occur
        within a message, including inside nested dictionaries and lists.

    @cvar _paths: Rooted paths (tuples of field names) whose values are
        sensitive. Lists within a message are transparent to path matching.
    """

    def __init__(self):
        self._lock = Lock()
        self._names = set()
        self._paths = set()

    def add(self, *paths):
        """
        Register sensitive field names or rooted field paths.

        A bare string registers a field name that will be redacted wherever
        it appears within a message, including inside nested dictionaries and
        lists. A sequence of strings registers a rooted path; e.g.
        C{("user", "password")} only matches the C{"password"} key of the
        top-level C{"user"} dictionary (nested lists are transparent to path
        matching). A L{eliot.Field} instance may also be given.
        """
        with self._lock:
            for path in paths:
                key_path = _as_path(path)
                if len(key_path) == 1:
                    self._names.add(key_path[0])
                else:
                    self._paths.add(key_path)

    def rules(self):
        """
        Return a snapshot C{(names, paths)} of the current registration.
        """
        with self._lock:
            return set(self._names), set(self._paths)

    def reset(self):
        """
        Remove all registered sensitive fields and paths.

        This is primarily useful for unit tests.
        """
        with self._lock:
            self._names.clear()
            self._paths.clear()


_sensitive_fields = SensitiveFields()


def add_sensitive_fields(*paths):
    """
    Register field names or rooted field paths whose values are sensitive and
    should be redacted from all logged messages.

    A bare string registers a field name that will be redacted wherever it
    appears within a message, including inside nested dictionaries and
    lists. A sequence of strings registers a rooted path; e.g.
    C{("user", "password")} only matches the C{"password"} key of the
    top-level C{"user"} dictionary. A L{eliot.Field} instance may also be
    given.
    """
    _sensitive_fields.add(*paths)


def _redact(value, names, paths, path, seen):
    """
    Recursively replace sensitive values within C{value}.

    @return: A C{(new_value, changed)} tuple, where C{changed} indicates
        whether any redaction took place. Containers are only copied when
        they (or their contents) were redacted, so unchanged objects are
        returned as-is and never mutated.
    """
    if isinstance(value, dict):
        marker = id(value)
        if marker in seen:
            return value, False
        seen.add(marker)
        result = {}
        changed = False
        for key, child in value.items():
            child_path = path + (key,)
            if key in names or child_path in paths:
                result[key] = REDACTED
                changed = True
            else:
                redacted_child, child_changed = _redact(
                    child, names, paths, child_path, seen
                )
                result[key] = redacted_child
                changed = changed or child_changed
        return result, changed
    if isinstance(value, list):
        marker = id(value)
        if marker in seen:
            return value, False
        seen.add(marker)
        result = []
        changed = False
        for child in value:
            # Lists are transparent: the rooted path does not grow when
            # descending into list items.
            redacted_child, child_changed = _redact(child, names, paths, path, seen)
            result.append(redacted_child)
            changed = changed or child_changed
        return result, changed
    if isinstance(value, tuple):
        marker = id(value)
        if marker in seen:
            return value, False
        seen.add(marker)
        result = []
        changed = False
        for child in value:
            redacted_child, child_changed = _redact(child, names, paths, path, seen)
            result.append(redacted_child)
            changed = changed or child_changed
        return tuple(result), changed
    return value, False


def redact_dictionary(dictionary, serializer=None):
    """
    Return a copy of C{dictionary} with all sensitive values redacted.

    Sensitive values are taken both from the global registration managed by
    L{add_sensitive_fields} and from L{eliot.Field} definitions marked
    C{sensitive=True} on the given serializer.

    If nothing sensitive is present the original dictionary is returned
    unchanged. Nested containers are copied only as needed to perform
    redaction, so the input dictionary and the objects it references are
    never mutated.

    @param dictionary: The message C{dict} about to be logged.

    @param serializer: Optionally, the L{eliot._validation._MessageSerializer}
        the message will be serialized with, whose L{eliot.Field} definitions
        may declare sensitive fields.
    """
    names, paths = _sensitive_fields.rules()
    if serializer is not None:
        fields = getattr(serializer, "fields", None)
        if fields:
            for field in fields.values():
                if getattr(field, "sensitive", False):
                    names.add(field.key)
    if not names and not paths:
        return dictionary
    redacted, changed = _redact(dictionary, names, paths, (), set())
    if not changed:
        return dictionary
    return redacted
