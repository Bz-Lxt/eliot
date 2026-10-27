"""
Tests for sensitive-field redaction (L{eliot._redaction}) and its
integration with the logging output path.
"""

from unittest import TestCase

from .. import (
    Field,
    MessageType,
    ActionType,
    MemoryLogger,
    Logger,
    log_message,
    start_action,
    add_sensitive_fields,
    register_exception_extractor,
    write_traceback,
    REDACTED,
)
from .._redaction import (
    _sensitive_fields,
    redact_dictionary,
    SensitiveFields,
)
from .._output import Destinations
from .._validation import _MessageSerializer
from .._message import (
    TASK_UUID_FIELD,
    TASK_LEVEL_FIELD,
    TIMESTAMP_FIELD,
    MESSAGE_TYPE_FIELD,
    EXCEPTION_FIELD,
    REASON_FIELD,
)
from .._action import ACTION_TYPE_FIELD, ACTION_STATUS_FIELD, FAILED_STATUS
from ..testing import assertContainsFields


class CustomException(Exception):
    """
    Custom exception used by exception-extraction tests.
    """


register_exception_extractor(
    CustomException,
    lambda e: {"password": "extracted-secret", "errno": 7},
)


class SensitiveFieldsRegistryTests(TestCase):
    """
    Tests for L{SensitiveFields}.
    """

    def setUp(self):
        self.registry = SensitiveFields()

    def test_add_name(self):
        """
        A bare string registers a sensitive field name.
        """
        self.registry.add("password")
        self.assertEqual(self.registry.rules(), ({"password"}, set()))

    def test_add_multiple(self):
        """
        Multiple names and paths can be registered in a single call.
        """
        self.registry.add("password", "token", ("user", "card"))
        self.assertEqual(
            self.registry.rules(),
            ({"password", "token"}, {("user", "card")}),
        )

    def test_add_path_as_list_or_tuple(self):
        """
        Rooted paths may be specified as lists or tuples of field names.
        """
        self.registry.add(["user", "password"], ("other", "token"))
        self.assertEqual(
            self.registry.rules(),
            (set(), {("user", "password"), ("other", "token")}),
        )

    def test_single_element_path_becomes_name(self):
        """
        A one-element path is equivalent to registering just that name, and
        therefore matches recursively at every level.
        """
        self.registry.add(("password",))
        self.assertEqual(self.registry.rules(), ({"password"}, set()))

    def test_add_field(self):
        """
        A L{Field} instance registers its key as a sensitive name.
        """
        self.registry.add(Field.for_types("card", [str], ""))
        self.assertEqual(self.registry.rules(), ({"card"}, set()))

    def test_invalid_path(self):
        """
        Anything that is not a string, a L{Field}, or a non-empty sequence
        of strings is rejected with L{TypeError}.
        """
        self.assertRaises(TypeError, self.registry.add, 123)
        self.assertRaises(TypeError, self.registry.add, [])
        self.assertRaises(TypeError, self.registry.add, ["ok", 123])

    def test_rules_is_snapshot(self):
        """
        L{SensitiveFields.rules} returns a snapshot: later registration does
        not mutate previously returned sets.
        """
        names, paths = self.registry.rules()
        self.registry.add("password")
        self.assertEqual(names, set())
        self.assertEqual(paths, set())

    def test_reset(self):
        """
        L{SensitiveFields.reset} removes all registered names and paths.
        """
        self.registry.add("password", ("user", "token"))
        self.registry.reset()
        self.assertEqual(self.registry.rules(), (set(), set()))


class RedactionTestCase(TestCase):
    """
    Base class that ensures global sensitive-field registration never leaks
    between tests.
    """

    def setUp(self):
        _sensitive_fields.reset()
        self.addCleanup(_sensitive_fields.reset)


class RedactDictionaryTests(RedactionTestCase):
    """
    Tests for L{redact_dictionary} operating directly on dictionaries.
    """

    def test_no_rules_returns_same_object(self):
        """
        With nothing sensitive registered, the original object is returned
        untouched.
        """
        message = {"a": 1, "b": {"c": [2, 3]}}
        self.assertIs(redact_dictionary(message), message)

    def test_name_top_level(self):
        """
        A registered sensitive name is redacted at the top level.
        """
        add_sensitive_fields("password")
        self.assertEqual(
            redact_dictionary({"password": "hunter2", "user": "bob"}),
            {"password": REDACTED, "user": "bob"},
        )

    def test_name_recursive(self):
        """
        A registered sensitive name is redacted recursively inside nested
        dictionaries, lists, and tuples.
        """
        add_sensitive_fields("password")
        message = {
            "keep": 1,
            "outer": {
                "password": "a",
                "inner": [{"password": "b"}, {"ok": "c"}],
                "t": ({"password": "d"},),
            },
        }
        self.assertEqual(
            redact_dictionary(message),
            {
                "keep": 1,
                "outer": {
                    "password": REDACTED,
                    "inner": [{"password": REDACTED}, {"ok": "c"}],
                    "t": ({"password": REDACTED},),
                },
            },
        )

    def test_sensitive_value_replaced_wholesale(self):
        """
        Once a sensitive key is matched, its entire value is replaced with
        the placeholder rather than being recursed into.
        """
        add_sensitive_fields("credentials")
        self.assertEqual(
            redact_dictionary({"credentials": {"user": "u", "password": "p"}}),
            {"credentials": REDACTED},
        )

    def test_rooted_path(self):
        """
        A rooted path only matches that exact location from the message
        root; the same key elsewhere is left alone.
        """
        add_sensitive_fields(("user", "password"))
        message = {
            "user": {"password": "X", "name": "n"},
            "other": {"password": "Y"},
        }
        self.assertEqual(
            redact_dictionary(message),
            {
                "user": {"password": REDACTED, "name": "n"},
                "other": {"password": "Y"},
            },
        )

    def test_rooted_path_list_transparent(self):
        """
        Lists are transparent to rooted path matching: list indices are not
        considered path components.
        """
        add_sensitive_fields(("users", "password"))
        message = {"users": [{"password": "a"}, {"password": "b"}], "ok": 1}
        self.assertEqual(
            redact_dictionary(message),
            {
                "users": [{"password": REDACTED}, {"password": REDACTED}],
                "ok": 1,
            },
        )

    def test_causal_metadata_unchanged(self):
        """
        Eliot's causal metadata and other non-sensitive fields are preserved
        exactly.
        """
        add_sensitive_fields("password")
        message = {
            TASK_UUID_FIELD: "uuid",
            TASK_LEVEL_FIELD: [1, 2],
            TIMESTAMP_FIELD: 123.0,
            MESSAGE_TYPE_FIELD: "test:message",
            "password": "secret",
            "n": 5,
        }
        redacted = redact_dictionary(message)
        assertContainsFields(
            self,
            redacted,
            {
                TASK_UUID_FIELD: "uuid",
                TASK_LEVEL_FIELD: [1, 2],
                TIMESTAMP_FIELD: 123.0,
                MESSAGE_TYPE_FIELD: "test:message",
                "password": REDACTED,
                "n": 5,
            },
        )

    def test_original_not_mutated(self):
        """
        The input dictionary and the nested objects it references are never
        mutated; redaction produces replacement containers.
        """
        add_sensitive_fields("password")
        nested = {"password": "deep", "keep": [1, 2]}
        message = {"password": "top", "nested": nested, "list": [nested]}
        redacted = redact_dictionary(message)

        # Original graph is completely untouched:
        self.assertEqual(message["password"], "top")
        self.assertIs(message["nested"], nested)
        self.assertEqual(nested, {"password": "deep", "keep": [1, 2]})
        self.assertIs(message["list"][0], nested)
        # The redacted copy differs where it should:
        self.assertEqual(redacted["password"], REDACTED)
        self.assertEqual(redacted["nested"]["password"], REDACTED)
        # Unchanged nested values are preserved:
        self.assertEqual(redacted["nested"]["keep"], [1, 2])

    def test_serializer_sensitive_fields(self):
        """
        Fields declared sensitive on a serializer's L{Field} definitions are
        redacted even without global registration.
        """
        token = Field.for_types("token", [str], "", sensitive=True)
        serializer = _MessageSerializer(
            [Field.for_value("message_type", "test:m", "The type"), token]
        )
        message = {"message_type": "test:m", "token": "abc", "ok": 1}
        self.assertEqual(
            redact_dictionary(message, serializer),
            {"message_type": "test:m", "token": REDACTED, "ok": 1},
        )

    def test_serializer_without_fields_attribute(self):
        """
        A serializer-like object without a C{fields} attribute is ignored
        gracefully.
        """

        class FakeSerializer(object):
            pass

        message = {"token": "abc"}
        self.assertIs(redact_dictionary(message, FakeSerializer()), message)


def make_logger():
    """
    Return a tuple of (L{Logger} with fresh isolated destinations, list of
    delivered messages).
    """
    logger = Logger()
    logger._destinations = Destinations()
    written = []
    logger._destinations.add(written.append)
    return logger, written


class FailingDestination(object):
    """
    A destination that records every message it sees and always raises.
    """

    def __init__(self, exception):
        self.exception = exception
        self.seen = []

    def __call__(self, message):
        self.seen.append(message)
        raise self.exception


class LoggerRedactionTests(RedactionTestCase):
    """
    End-to-end tests through the production L{Logger}.
    """

    def test_log_message_redacted_before_destinations(self):
        """
        Fields of a L{eliot.log_message} message registered globally are
        redacted before delivery to destinations.
        """
        add_sensitive_fields("password")
        logger, written = make_logger()
        log_message(
            "test:login",
            user="bob",
            password="hunter2",
            details={"keep": 1, "nested": [{"password": "x"}]},
            __eliot_logger__=logger,
        )
        (message,) = written
        assertContainsFields(
            self,
            message,
            {
                MESSAGE_TYPE_FIELD: "test:login",
                "user": "bob",
                "password": REDACTED,
                "details": {"keep": 1, "nested": [{"password": REDACTED}]},
            },
        )

    def test_field_sensitive_via_message_type(self):
        """
        A L{Field} declared sensitive on a L{MessageType} is redacted when
        the message is logged.
        """
        message_type = MessageType(
            "test:message",
            [
                Field.for_types("secret", [str], "", sensitive=True),
                Field.for_types("ok", [str], ""),
            ],
            "",
        )
        logger, written = make_logger()
        message_type.log(secret="shh", ok="fine", __eliot_logger__=logger)
        (message,) = written
        assertContainsFields(
            self,
            message,
            {
                MESSAGE_TYPE_FIELD: "test:message",
                "secret": REDACTED,
                "ok": "fine",
            },
        )

    def test_field_sensitive_via_action_type(self):
        """
        Sensitive start and success fields of an L{ActionType} are redacted,
        while action metadata is preserved.
        """
        action_type = ActionType(
            "test:action",
            [Field.for_types("token", [str], "", sensitive=True)],
            [Field.for_types("result", [str], "", sensitive=True)],
            "",
        )
        logger, written = make_logger()
        with action_type(logger, token="tok") as action:
            action.add_success_fields(result="res")
        start, success = written
        assertContainsFields(
            self,
            start,
            {
                ACTION_TYPE_FIELD: "test:action",
                "action_status": "started",
                "token": REDACTED,
            },
        )
        assertContainsFields(
            self,
            success,
            {
                ACTION_TYPE_FIELD: "test:action",
                "action_status": "succeeded",
                "result": REDACTED,
            },
        )
        self.assertEqual(start[TASK_UUID_FIELD], success[TASK_UUID_FIELD])
        self.assertEqual(start[TASK_LEVEL_FIELD], [1])
        self.assertEqual(success[TASK_LEVEL_FIELD], [2])

    def test_exception_extraction_fields_redacted(self):
        """
        Fields produced by a registered exception extractor in failed action
        messages are redacted according to global registration; the
        exception type and other causal fields remain.
        """
        add_sensitive_fields("password")
        logger = MemoryLogger()
        action = start_action(logger, "test:login")
        try:
            with action.context():
                raise CustomException("bad password")
        except CustomException as exception:
            action.finish(exception)

        failures = [
            m for m in logger.messages if m.get(ACTION_STATUS_FIELD) == FAILED_STATUS
        ]
        (failure,) = failures
        assertContainsFields(
            self,
            failure,
            {
                ACTION_TYPE_FIELD: "test:login",
                ACTION_STATUS_FIELD: FAILED_STATUS,
                "password": REDACTED,
                "errno": 7,
                EXCEPTION_FIELD: "%s.%s"
                % (CustomException.__module__, CustomException.__name__),
                REASON_FIELD: "bad password",
            },
        )

    def test_traceback_extracted_fields_redacted(self):
        """
        Exception-extracted fields included in L{eliot.write_traceback}
        messages are redacted.
        """
        add_sensitive_fields("password")
        logger, written = make_logger()
        try:
            raise CustomException("bad password")
        except CustomException:
            write_traceback(logger)

        (message,) = written
        assertContainsFields(
            self,
            message,
            {"message_type": "eliot:traceback", "password": REDACTED},
        )

    def test_passed_dictionary_unmodified(self):
        """
        The dictionary (including nested values) passed to L{Logger.write}
        is not modified, even though destinations receive a redacted copy.
        """
        add_sensitive_fields("password")
        logger, written = make_logger()
        nested = {"password": "deep", "keep": 1}
        dictionary = {"password": "top", "nested": nested}
        logger.write(dictionary)

        self.assertEqual(dictionary, {"password": "top", "nested": nested})
        self.assertEqual(nested, {"password": "deep", "keep": 1})
        self.assertEqual(
            written[0],
            {"password": REDACTED, "nested": {"password": REDACTED, "keep": 1}},
        )

    def test_destination_failure_diagnostic_redacted(self):
        """
        When a destination fails, the C{eliot:destination_failure}
        diagnostic message embeds the already-redacted message rather than
        the original sensitive values.
        """
        add_sensitive_fields("password")
        logger = Logger()
        logger._destinations = Destinations()
        destination = FailingDestination(RuntimeError("ono"))
        logger._destinations.add(destination)

        logger.write({"hello": 123, "password": "hunter2"})

        # The failing destination itself only ever saw the redacted copy:
        self.assertEqual(destination.seen[0]["password"], REDACTED)
        # The failure diagnostic embeds the redacted rendering:
        failure_message = destination.seen[1]
        assertContainsFields(
            self,
            failure_message,
            {"message_type": "eliot:destination_failure"},
        )
        self.assertIn(REDACTED, failure_message["message"])
        self.assertNotIn("hunter2", failure_message["message"])
        # And the diagnostic still carries causal metadata:
        self.assertIn(TASK_UUID_FIELD, failure_message)
        self.assertIn(TASK_LEVEL_FIELD, failure_message)

    def test_serialization_failure_diagnostic_redacted(self):
        """
        When serialization fails, the C{eliot:serialization_failure}
        diagnostic embeds the redacted message rather than original
        sensitive values.
        """

        def raiser(value):
            raise RuntimeError("oops")

        serializer = _MessageSerializer(
            [
                Field.for_value("message_type", "mymessage", "The type"),
                Field("fail", raiser, "Serialization fail"),
            ]
        )
        add_sensitive_fields("password")
        logger, written = make_logger()
        logger.write(
            {"message_type": "mymessage", "fail": "will", "password": "hunter2"},
            serializer,
        )

        self.assertEqual(len(written), 2)
        assertContainsFields(
            self, written[1], {"message_type": "eliot:serialization_failure"}
        )
        self.assertIn(REDACTED, written[1]["message"])
        self.assertNotIn("hunter2", written[1]["message"])
        # Both keys and values are rendered with repr() by the diagnostic:
        self.assertEqual(
            eval(written[1]["message"]),
            {
                repr("message_type"): repr("mymessage"),
                repr("fail"): repr("will"),
                repr("password"): repr(REDACTED),
            },
        )


class MemoryLoggerRedactionTests(RedactionTestCase):
    """
    L{MemoryLogger} applies the same redaction as the production L{Logger}.
    """

    def test_redacts_stored_messages(self):
        """
        Messages stored by L{MemoryLogger} have sensitive values redacted.
        """
        add_sensitive_fields("password")
        logger = MemoryLogger()
        logger.write({"password": "x", "ok": 1, "nested": {"password": "y"}})
        self.assertEqual(
            logger.messages,
            [{"password": REDACTED, "ok": 1, "nested": {"password": REDACTED}}],
        )

    def test_validate_sensitive_typed_field(self):
        """
        L{MemoryLogger.validate} accepts the redaction placeholder in a
        sensitive L{Field} whose original type was not a string.
        """
        message_type = MessageType(
            "test:typed",
            [Field.for_types("count", [int], "", sensitive=True)],
            "",
        )
        logger = MemoryLogger()
        message_type.log(count=42, __eliot_logger__=logger)
        logger.validate()
        self.assertEqual(logger.messages[0]["count"], REDACTED)

    def test_passed_dictionary_unmodified(self):
        """
        The dictionary passed to L{MemoryLogger.write} is not modified.
        """
        add_sensitive_fields("password")
        logger = MemoryLogger()
        nested = {"password": "y"}
        dictionary = {"password": "x", "nested": nested}
        logger.write(dictionary)
        self.assertEqual(dictionary, {"password": "x", "nested": nested})
        self.assertEqual(nested, {"password": "y"})

    def test_unchanged_message_identity(self):
        """
        With no sensitive fields registered, the exact object passed in is
        stored.
        """
        logger = MemoryLogger()
        message = {"a": 1}
        logger.write(message)
        self.assertIs(logger.messages[0], message)


class PublicAPITests(TestCase):
    """
    The redaction API is exposed from the top-level L{eliot} module.
    """

    def test_add_sensitive_fields_callable(self):
        """
        L{eliot.add_sensitive_fields} and the C{camelCase} alias register
        sensitive fields globally.
        """
        import eliot

        self.assertIs(eliot.add_sensitive_fields, eliot.addSensitiveFields)
        self.addCleanup(_sensitive_fields.reset)
        eliot.add_sensitive_fields("password", ("a", "b"))
        self.assertEqual(
            _sensitive_fields.rules(),
            ({"password"}, {("a", "b")}),
        )
