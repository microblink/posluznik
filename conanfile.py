from conan import ConanFile
from conan.tools.files import copy

from os.path import join

class PosluznikConan(ConanFile):
    name = 'posluznik'
    version = '1.0.4'
    settings = 'os', 'arch'

    package_type = 'application'

    no_copy_source = False

    def build_requirements(self):
        self.tool_requires('cargo/1.74.0')

    def layout(self):
        self.folders.generators = 'target'
        self.folders.source = 'src'

    def build(self):
        self.run("cargo build --release")

    def package(self):
        copy(self, 'posluznik', dst=join(self.package_folder, 'bin'), src=join(self.build_folder, 'target', 'release'))

    exports_sources = [
        'src/*',
        'Cargo.toml',
        'Cargo.lock',
    ]

    def package_info(self):
        self.cpp_info.includedirs = []
        self.cpp_info.libdirs     = []