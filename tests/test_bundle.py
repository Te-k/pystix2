from pystix2 import Bundle, Domain, Malware, IntrusionSet, ThreatActor


class TestBundle:
    def test_creation(self):
        b = Bundle()
        d = Domain("google.com")
        b.add(d)
        m = Malware(name="Pegasus")
        b.add(m)
        i = IntrusionSet()
        i.name = "PegasusStuff"
        b.add(i)
        t = ThreatActor()
        t.name = "NSO Group"
        b.add(t)
        b.to_json()

