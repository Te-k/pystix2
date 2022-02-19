import os
from pystix2 import Bundle
from utils import get_data_folder


class TestSTIXParsing:
    def test_parsing_pegasus(self):
        file = os.path.join(get_data_folder(), "pegasus.stix2")
        with open(file) as f:
            data = f.read()
        bd = Bundle.from_json(data)
        assert len(bd.objects) == 3035
        assert len(bd.indicators) == 1517
        assert len(bd.relationships) == 1517
        assert len(bd.domains) == 1412

    def test_parsing_apt1(self):
        file = os.path.join(get_data_folder(), "apt1.json")
        with open(file) as f:
            data = f.read()
        bd = Bundle.from_json(data)
        assert len(bd.objects) == 76
        assert len(bd.indicators) == 12
        assert len(bd.relationships) == 30

