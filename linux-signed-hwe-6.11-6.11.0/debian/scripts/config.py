class Signing:

    def __init__(self):
        self._flavour_to_arch = {}
        self._package_to_flavour_to_arch = {}
        self._arch_flavour_data = {}

    def add(self, arch, stype, binary, flavours, options):
        for flavour in flavours:
            self._arch_flavour_data.setdefault((arch, flavour), set()).add((stype, binary))
            self._flavour_to_arch.setdefault(flavour, set()).add(arch)
            if "extra" in options:
                # cvm & uc sometimes need modules-extra
                self._package_to_flavour_to_arch.setdefault("extra", {}).setdefault(flavour, set()).add(arch)
            # cvm is an exclusive option: no image paragraph
            if "cvm" in options:
                self._package_to_flavour_to_arch.setdefault("cvm", {}).setdefault(flavour, set()).add(arch)
                continue
            # uc is an exclusive option: no image paragraph
            if "uc" in options:
                self._package_to_flavour_to_arch.setdefault("uc", {}).setdefault(flavour, set()).add(arch)
                continue
            self._package_to_flavour_to_arch.setdefault("image", {}).setdefault(flavour, set()).add(arch)
            # all other options are supplementary to the image
            if "di" in options:
                self._package_to_flavour_to_arch.setdefault("di", {}).setdefault(flavour, set()).add(arch)
            if "hmac" in options:
                self._package_to_flavour_to_arch.setdefault("hmac", {}).setdefault(flavour, set()).add(arch)

    @property
    def flavour_archs(self):
        for flavour, archs in sorted(self._flavour_to_arch.items()):
            yield flavour, sorted(list(archs))

    def package_flavour_archs(self, package):
        for flavour, archs in sorted(self._package_to_flavour_to_arch.get(package, {}).items()):
            yield flavour, sorted(list(archs))

    @property
    def arch_flavour_data(self):
        # allow for more than one binary to be signed by an arch+flavour pair
        # maintain backwards compatible API
        for (arch, flavour), stypebins in sorted(self._arch_flavour_data.items()):
            for (stype, binary) in sorted(stypebins):
                yield (arch, flavour), (stype, binary)

    @classmethod
    def load(cls, config):
        signing = Signing()
        with open(config) as cfd:
            for line in cfd:
                cmd, *args = line.strip().split()
                if cmd == "sign":
                    arch, stype, binary, *flavours = args
                    options = []
                    while flavours[-1].startswith("--"):
                        options.append(flavours.pop()[2:])
                    signing.add(arch, stype, binary, flavours, options)
        return signing
