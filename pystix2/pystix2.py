#! /usr/bin/env python
from datetime import datetime, date
from dateutil.parser import parse
import uuid
import stringcase
import json
import re


class UndefinedIndicatorException(Exception):
    pass

class InvalidSTIXFormat(Exception):
    pass


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))


class Bundle(object):
    """
    Class that provides bundle of other STIX objects
    """
    def __init__(self):
        self._id = "bundle-" + str(uuid.uuid4())
        self._objects = []

    def get(self, type: str) -> list:
        if type == "indicators":
            return [obj for obj in self.objects if isinstance(obj, Indicator) or issubclass(obj.__class__, Indicator)]
        elif type == "relationships":
            return [obj for obj in self.objects if isinstance(obj, Relationship)]
        elif type == "domains":
            return [obj for obj in self.objects if isinstance(obj, Domain)]
        elif type == "processes":
            return [obj for obj in self.objects if isinstance(obj, Process)]
        elif type == "emails":
            return [obj for obj in self.objects if isinstance(obj, Email)]
        return []

    @property
    def indicators(self) -> list:
        return self.get("indicators")

    @property
    def relationships(self) -> list:
        return self.get("relationships")

    @property
    def domains(self) -> list:
        return self.get("domains")

    @property
    def processes(self) -> list:
        return self.get("processes")

    @property
    def emails(self) -> list:
        return self.get("emails")

    @property
    def objects(self):
        return self._objects

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value: str) -> None:
        self._id = value

    def add(self, obj):
        self._objects.append(obj)

    def to_struct(self):
        """
        Return structure of the bundle that can be serializide to JSON
        """
        return {
            "type": "bundle",
            "id": self.id,
            "objects": [obj.to_struct() for obj in self.objects]
        }

    def to_json(self, pretty=True):
        if pretty:
            return json.dumps(
                self.to_struct(),
                indent=4,
                default=json_serial
            )
        else:
            return json.dumps(self.to_struct(), default=json_serial)

    @staticmethod
    def from_file(path: str) -> object:
        with open(path) as f:
            data = f.read()
        return Bundle.from_json(data)

    @staticmethod
    def from_json(data: str):
        pd = json.loads(data)
        return Bundle.from_struct(pd)

    @staticmethod
    def from_struct(data):
        b = Bundle()
        if "type" not in data:
            raise InvalidSTIXFormat()
        if data["type"] != "bundle":
            raise InvalidSTIXFormat()
        b.id = data["id"]
        for obj in data.get("objects", []):
            b.add(StixObject.from_struct(obj))

        return b


class StixObject(object):
    """
    Class that implements STIX Domain Objects
    """
    def __init__(self, id=None):
        if id:
            self._id = id
        else:
            self._id = stringcase.spinalcase(self.__class__.__name__) + "--" + str(uuid.uuid4())
        self._creation_time = datetime.now()
        self._modification_time = datetime.now()

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value: str) -> None:
        self._id = value

    @property
    def creation_time(self):
        return self._creation_time

    @creation_time.setter
    def creation_time(self, value):
        if isinstance(value, str):
            self._creation_time = parse(value)
        else:
            self._creation_time = value

    @property
    def modification_time(self):
        return self._modification_time

    @modification_time.setter
    def modification_time(self, value):
        if isinstance(value, str):
            self._modification_time = parse(value)
        else:
            self._modification_time = value

    def to_struct(self):
        raise NotImplementedError()

    def to_json(self, pretty=True):
        if pretty:
            return json.dumps(
                self.to_struct(),
                indent=4,
                default=json_serial
            )
        else:
            return json.dumps(self.to_struct(), default=json_serial)

    @staticmethod
    def from_json(data):
        pd = json.loads(data)
        return StixObject.from_struct(pd)

    @staticmethod
    def from_struct(data):
        """
        Create STIX Object from data
        """
        if data.get("type", "") == "malware":
            return Malware.from_struct(data)
        elif data.get("type", "") == "indicator":
            return Indicator.from_struct(data)
        elif data.get("type", "") == "relationship":
            return Relationship.from_struct(data)
        elif data.get("type", "") == "intrusion-set":
            return IntrusionSet.from_struct(data)
        elif data.get("type", "") == "threat-actor":
            return ThreatActor.from_struct(data)
        elif data.get("type", "") == "identity":
            return Identity.from_struct(data)
        elif data.get("type", "") == "tool":
            return Tool.from_struct(data)
        elif data.get("type", "") == "attack-pattern":
            return AttackPattern.from_struct(data)
        elif data.get("type", "") == "report":
            return Report.from_struct(data)
        else:
            print(data["type"])
            raise NotImplementedError()

    def __repr__(self):
        return f"<{self.__class__.__name__}>"


class Malware(StixObject):
    def __init__(self, name=None, description="", is_family=False):
        self._name = name
        self._description = description
        self._is_family = is_family
        super().__init__()
        self._id = "malware--" + str(uuid.uuid4())


    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value: str) -> None:
        self._description = value

    @property
    def is_family(self):
        return self._is_family

    @is_family.setter
    def is_family(self, value: bool) -> None:
        self._is_family = value

    def to_struct(self):
        return {
            "type": "malware",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "description": self.description,
            "is_family": self.is_family
        }

    @staticmethod
    def from_struct(data):
        m = Malware()
        m.id = data.get("id", "")
        m.name = data.get("name", "")
        m.description = data.get("description", "")
        m.is_family = data.get("is_family", False)
        return m


class Indicator(StixObject):
    """
    Indicator
    """
    def __init__(self, value=None, type=None):
        super().__init__()
        self._type = type
        self._value = value
        self._valid_from = None
        self._id = "indicator--" + str(uuid.uuid4())
        self._indicator_types = []
        self._pattern = ""

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @property
    def type(self):
        return self._type

    @property
    def indicator_types(self):
        return self._indicator_types

    @property
    def valid_from(self):
        return self._valid_from

    @valid_from.setter
    def valid_from(self, value):
        self._valid_from = value

    @property
    def pattern(self):
        if isinstance(self, Indicator):
            return self._pattern
        else:
            return f"[{self.pattern_name}='{self.value}']"

    @pattern.setter
    def pattern(self, value: str) -> None:
        self._pattern = value

    def to_struct(self):
        """
        Convert to a structure
        """
        return {
            "type": "indicator",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "indicator_types": self.indicator_types,
            "pattern": self.pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": self.valid_from
        }

    @staticmethod
    def parse_patterns(pattern):
        patterns = []
        for entry in re.split(" (AND|OR) ", pattern.strip("[]")):
            if entry.strip() == "AND" or entry.strip() == "OR":
                continue
            obj = re.match(r"([\w\.\:\-]+)\s*=\s*'([^\']*)'", entry)
            if obj:
                patterns.append([obj.group(1), obj.group(2)])

            else:
                print(entry)
                raise InvalidSTIXFormat()

        return patterns

    @staticmethod
    def from_struct(data: dict) -> StixObject:
        patterns = Indicator.parse_patterns(data.get("pattern", ""))
        objc = Indicator
        if len(patterns) == 1:
            for sub in Indicator.__subclasses__():
                if patterns[0][0] == sub.pattern_name:
                    objc = sub

        obj = objc()
        obj.id = data.get("id", "")
        obj.creation_time = parse(data["created"])
        obj.modification_time = parse(data["modified"])
        obj.valid_from = parse(data["valid_from"])
        if objc == Indicator:
            obj.pattern = data.get("pattern", "")
        else:
            obj.value = patterns[0][1]
        return obj

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.value})>"


class Domain(Indicator):
    """
    Indicator of a domain
    """
    pattern_name = "domain-name:value"
    def __init__(self, value=None):
        super().__init__(value=value, type="domain")


class Email(Indicator):
    """
    Indicator of an email address
    """
    pattern_name = "email-addr:value"
    def __init__(self, value=None):
        super().__init__(value=value, type="email")


class FileMD5(Indicator):
    """
    Indicator of a md5 of a file
    """
    pattern_name = "file:hashes.md5"
    def __init__(self, value=None):
        super().__init__(value=value, type="file-md5")


class FileName(Indicator):
    """
    Indicator of a file name
    """
    pattern_name = "file:name"
    def __init__(self, value=None):
        super().__init__(value=value, type="file-name")


class Process(Indicator):
    """
    Indicator of a process name
    """
    pattern_name = "process:name"
    def __init__(self, value=None):
        super().__init__(value=value, type="process")


class Relationship(StixObject):
    """
    Relationship object
    """
    def __init__(self, id=None, type="indicates", source=None, target=None):
        super().__init__()
        if id:
            self._id = id
        else:
            self._id = "relationship--" + str(uuid.uuid4())
        self._type = type
        self._source = source
        self._target = target

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value: str) -> None:
        self._type = value

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value: str) -> None:
        self._source = value

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value: str) -> None:
        self._target = value

    def to_struct(self):
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "relationship_type": self.type,
            "source_ref": self.source,
            "target_ref": self.target
        }

    @staticmethod
    def from_struct(data):
        obj = Relationship()
        obj.id = data.get("id", "")
        obj.type = data.get("type", "")
        obj.source = data.get("source_ref", "")
        obj.target = data.get("target_ref", "")
        obj.creation_time = data["created"]
        obj.modification_time = data["modified"]
        return obj


class IntrusionSet(StixObject):
    """
    Intrusion Set
    """
    def __init__(self, id=None, name=None, description="", resource_level="government", primary_motivation=""):
        super().__init__()
        if id:
            self._id = id
        else:
            self._id = "intrusion-set--" + str(uuid.uuid4())
        self._name = name
        self._description = description
        self._resource_level = resource_level
        self._primary_motivation = primary_motivation
        self._aliases = []
        self._first_seen = None

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str) -> None:
        self._description = value

    @property
    def resource_level(self) -> str:
        return self._resource_level

    @resource_level.setter
    def resource_level(self, value: str) -> None:
        self._resource_level = value

    @property
    def first_seen(self):
        return self._first_seen

    @first_seen.setter
    def first_seen(self, value):
        self._first_seen = value

    @property
    def primary_motivation(self):
        return self._primary_motivation

    @primary_motivation.setter
    def primary_motivation(self, value):
        self._primary_motivation = value

    @property
    def aliases(self) -> list:
        return self._aliases

    @aliases.setter
    def aliases(self, value: list) -> None:
        self._aliases = value

    def to_struct(self):
        return {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "description": self.description,
            "first_seen": self.first_seen,
            "resource_level": self.resource_level,
            "primary_motivation": self.primary_motivation,
            "aliases": self.aliases,
        }


    @staticmethod
    def from_struct(data: dict) -> StixObject:
        obj = IntrusionSet()
        obj.name = data.get("name", "")
        obj.id = data.get("id", "")
        obj.creation_time = data["created"]
        obj.modification_time = data["modified"]
        obj.description = data.get("description", "")
        obj.resource_level = data.get("resource_level", "")
        obj.primary_motivation = data.get("primary_motivation", "")
        obj.aliases = data.get("aliases", [])
        return obj


class ThreatActor(StixObject):
    """
    Threat Actor
    """
    def __init__(self, id=None, name=None, threat_actor_types=None, roles=None, resource_level=None, aliases=None, primary_motivation=None):
        super().__init__()
        if id:
            self._id = id
        else:
            self._id = "threat-actor--" + str(uuid.uuid4())
        self._name = name
        if threat_actor_types:
            self._threat_actor_types = threat_actor_types
        else:
            self._threat_actor_types = []
        if roles:
            self._roles = roles
        else:
            self._roles = []
        self._resource_level = resource_level
        if aliases:
            self._aliases = aliases
        else:
            self._aliases = []
        self._primary_motivation = primary_motivation

    @property
    def threat_actor_types(self):
        return self._threat_actor_types

    @threat_actor_types.setter
    def threat_actor_types(self, value):
        self._threat_actor_types = value

    @property
    def roles(self) -> list:
        return self._roles

    @roles.setter
    def roles(self, value: list) -> None:
        self._roles = value

    @property
    def resource_level(self):
        return self._resource_level

    @resource_level.setter
    def resource_level(self, value):
        self._resource_level = value

    @property
    def aliases(self):
        return self._aliases

    @aliases.setter
    def aliases(self, value: list) -> None:
        self._aliases = value

    @property
    def primary_motivation(self):
        return self._primary_motivation

    @primary_motivation.setter
    def primary_motivation(self, value):
        return self._primary_motivation

    def to_struct(self) -> dict:
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "threat_actor_types": self.threat_actor_types,
            "roles": self.roles,
            "resource_level": self.resource_level,
            "aliases": self.aliases,
            "primary_motivation": self.primary_motivation
        }

    @staticmethod
    def from_struct(data: dict) -> StixObject:
        obj = ThreatActor()
        obj.name = data.get("name", "")
        obj.id = data.get("id", "")
        obj.creation_time = parse(data["created"])
        obj.modification_time = parse(data["modified"])
        obj.threat_actor_types = data.get("threat_actor_types", [])
        obj.roles = data.get("roles", [])
        obj.aliases = data.get("aliases", [])
        obj.resource_level = data.get("resource_level", "")
        obj.primary_motivation = data.get("primary_motivation", "")
        obj.aliases = data.get("aliases", [])
        return obj


class Identity(StixObject):
    """
    Identity
    """
    def __init__(self, id=None, name=None, identity_class=None, sectors=None, contact_information=None):
        super().__init__()
        self._name = name
        self._identity_class = identity_class
        if id:
            self.id = id
        else:
            self.id = "identity--" + str(uuid.uuid4())
        if sectors:
            self._sectors = sectors
        else:
            self._sectors = []
        self._contact_information = contact_information

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def identity_class(self):
        return self._identity_class

    @identity_class.setter
    def identity_class(self, value):
        self._identity_class = value

    @property
    def sectors(self) -> list:
        return self._sectors

    @sectors.setter
    def sectors(self, value: list) -> None:
        self._sectors = value

    @property
    def contact_information(self):
        return self._contact_information

    @contact_information.setter
    def contact_information(self, value):
        self._contact_information = value

    def to_struct(self) -> dict:
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "identity_class": self.identity_class,
            "sectors": self.sectors,
            "contact_information": self.contact_information
        }

    @staticmethod
    def from_struct(data):
        obj = Identity()
        obj.id = data.get("id", "")
        obj.creation_time = data["created"]
        obj.modification_time = data["modified"]
        obj.name = data.get("name", "")
        obj.identity_class = data.get("identity_class", "")
        obj.sectors = data.get("sectors", [])
        obj.contact_information = data.get("contact_information", "")
        return obj


class Tool(StixObject):
    """
    Tool
    """
    def __init__(self, id=None, name=None, tool_types=None, description="", kill_chain_phases=None):
        super().__init__(id=id)
        self._name = name
        self._tool_types = tool_types
        self._description = description
        self._kill_chain_phases = kill_chain_phases

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def tool_types(self) -> list:
        return self._tool_types

    @tool_types.setter
    def tool_types(self, value: list) -> None:
        self._tool_types = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def kill_chain_phases(self) -> list:
        return self._kill_chain_phases

    @kill_chain_phases.setter
    def kill_chain_phases(self, value):
        self._kill_chain_phases = value

    def to_struct(self) -> dict:
        return {
            "type": "tool",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "tool_types": self.tool_types,
            "description": self.description,
            "kill_chain_phases": self.kill_chain_phases
        }

    @staticmethod
    def from_struct(data) -> StixObject:
        obj = Tool()
        obj.id = data.get("id", None)
        obj.name = data.get("name", "")
        obj.description = data.get("description", "")
        obj.tool_types = data.get("tool_types", [])
        obj.kill_chain_phases = data.get("kill_chain_phases", [])
        return obj

class AttackPattern(StixObject):
    """
    Attack Pattern
    """
    def __init__(self, id=None, name=None, description=None, external_references=None, kill_chain_phases=None):
        super().__init__(id=id)
        self._name = name
        self._description = description
        if external_references:
            self._external_references = external_references
        else:
            self._external_references = []
        if kill_chain_phases:
            self._kill_chain_phases = kill_chain_phases
        else:
            self._kill_chain_phases = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def external_references(self):
        return self._external_references

    @external_references.setter
    def external_references(self, value):
        self._external_references = value

    @property
    def kill_chain_phases(self):
        return self._kill_chain_phases

    @kill_chain_phases.setter
    def kill_chain_phases(self, value):
        self._kill_chain_phases = value

    def to_struct(self) -> dict:
        return {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "description": self.description,
            "external_references": self.external_references,
            "kill_chain_phases": self.kill_chain_phases
        }

    @staticmethod
    def from_struct(data):
        obj = AttackPattern()
        obj.id = data.get("id", "")
        obj.creation_time = data["created"]
        obj.modification_time = data["modified"]
        obj.name = data.get("name", "")
        obj.description = data.get("description", "")
        obj.external_references = data.get("external_references", [])
        obj.kill_chain_phases = data.get("kill_chain_phases", [])
        return obj


class Report(StixObject):
    def __init__(self, id=None, name=None, report_types=None, published=None, description=None, objects_refs=None):
        super().__init__(id=id)
        self._name = name
        if report_types:
            self._report_types = report_types
        else:
            self._report_types = []
        self._publication_time = published
        self._description = description
        if objects_refs:
            self._objects_refs = objects_refs
        else:
            self._objects_refs = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def report_types(self):
        return self._report_types

    @report_types.setter
    def report_types(self, value):
        self._report_types = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def publication_time(self):
        return self._publication_time

    @publication_time.setter
    def publication_time(self, value):
        if isinstance(value, str):
            self._publication_time = parse(value)
        else:
            self._publication_time = value

    @property
    def objects_refs(self):
        return self._objects_refs

    @objects_refs.setter
    def objects_refs(self, value: list) -> None:
        self._objects_refs = value

    def to_struct(self) -> dict:
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.creation_time,
            "modified": self.modification_time,
            "name": self.name,
            "report_types": self.report_types,
            "description": self.description,
            "objects_refs": self.objects_refs
        }

    @staticmethod
    def from_struct(data):
        obj = Report()
        obj.id = data.get("id", "")
        obj.creation_time = data["created"]
        obj.modification_time = data["modified"]
        obj.name = data.get("name", "")
        obj.description = data.get("description", "")
        obj.report_types = data.get("report_types", [])
        obj.objects_refs = data.get("objects_refs", [])
        return obj
