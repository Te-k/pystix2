from pystix2 import Bundle, Domain, Malware, IntrusionSet, ThreatActor, Indicator


class TestIndicator:
    def test_creation(self):
        i = Indicator()
        i.pattern = "[domain-name:value='example.org']"
        i.to_json()


