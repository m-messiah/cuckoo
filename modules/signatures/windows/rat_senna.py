# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Senna(Signature):
    name = "senna"
    description = "Creates known Senna Spy files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["senna"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Senna\\ Spy\\ Fenasoft\\ 2000\\ Virus",
        ".*Senna\\ Spy\\ Rock\\ In\\ Rio\\ 2001\\ Virus",
        ".*Senna\\ Spy\\ Virus",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
