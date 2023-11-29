from six import StringIO
from conan import ConanFile

class PosluznikTestPackageConan(ConanFile):
    generators = "VirtualBuildEnv"
    test_type  = "explicit"

    def layout(self):
        # do not care
        self.folders.generators = 'build'

    def build_requirements(self):
        self.tool_requires(self.tested_reference_str)

    def test(self):
        self.run("posluznik --version")

    def build(self):
        pass