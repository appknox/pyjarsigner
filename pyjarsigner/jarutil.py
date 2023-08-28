# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see
# <http://www.gnu.org/licenses/>.


"""
Module and utility for creating, modifying, signing, or verifying
Java archives

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL
"""

import os

from shutil import copyfile
from tempfile import NamedTemporaryFile
from zipfile import ZipFile, ZIP_STORED

from .manifest import file_matches_sigfile, Manifest, SignatureManifest
from .crypto import private_key_type
from .crypto import verify_signature_block, SignatureBlockVerificationError


class VerificationError(Exception):
    pass


class SignatureBlockFileVerificationError(VerificationError):
    pass


class ManifestChecksumError(VerificationError):
    pass


class JarChecksumError(VerificationError):
    pass


class JarSignatureMissingError(VerificationError):
    pass


class MissingManifestError(Exception):
    pass


def verify(certificate, jar_file, sf_name=None):
    """
    Verifies signature of a JAR file.

    Limitations:
    - diagnostic is less verbose than of jarsigner
    :return None if verification succeeds.
    :exception SignatureBlockFileVerificationError, ManifestChecksumError,
        JarChecksumError, JarSignatureMissingError

    Reference:
    http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Signature_Validation
    Note that the validation is done in three steps. Failure at any step is a
    failure of the whole validation.
    """  # noqua

    # Step 0: get the "key alias", used also for naming of sig-related files.
    zip_file = ZipFile(jar_file)
    sf_files = list(filter(file_matches_sigfile, zip_file.namelist()))

    if len(sf_files) == 0:
        raise JarSignatureMissingError("No .SF file in %s" % jar_file)
    elif len(sf_files) > 1:
        if sf_name is None:
            msg = (
                "Multiple .SF files in %s, but SF_NAME.SF not specified"
                % jar_file)
            raise VerificationError(msg)
        elif ('META-INF/' + sf_name) in sf_files:
            sf_filename = 'META-INF/' + sf_name
        else:
            msg = (
                "No .SF file in %s named META-INF/%s (found %d .SF files)"
                % (jar_file, sf_name, len(sf_files)))
            raise VerificationError(msg)
    elif len(sf_files) == 1:
        if sf_name is None:
            sf_filename = sf_files[0]
        elif sf_files[0] == 'META-INF/' + sf_name:
            sf_filename = sf_files[0]
        else:
            msg = "No .SF file in %s named META-INF/%s" % (jar_file, sf_name)
            raise VerificationError(msg)

    key_alias = sf_filename[9:-3]  # "META-INF/%s.SF"
    sf_data = zip_file.read(sf_filename)

    # Step 1: check the crypto part.
    file_list = zip_file.namelist()
    sig_block_filename = None

    # JAR specification mentions only RSA and DSA; jarsigner also has EC
    # TODO: what about "SIG-*"?
    signature_extensions = ("RSA", "DSA", "EC")
    for extension in signature_extensions:
        candidate_filename = "META-INF/%s.%s" % (key_alias, extension)
        if candidate_filename in file_list:
            sig_block_filename = candidate_filename
            break

    if sig_block_filename is None:
        msg = "None of %s found in JAR" % \
              ", ".join(key_alias + "." + x for x in signature_extensions)
        raise JarSignatureMissingError(msg)

    sig_block_data = zip_file.read(sig_block_filename)
    try:
        verify_signature_block(certificate, sf_data, sig_block_data)
    except SignatureBlockVerificationError as message:
        message = "Signature block verification failed: %s" % message
        raise SignatureBlockFileVerificationError(message)

    # KEYALIAS.SF is correctly signed.
    # Step 2: Check that it contains correct checksum of the manifest.
    signature_manifest = SignatureManifest()
    signature_manifest.parse(sf_data)

    jar_manifest = Manifest()
    jar_manifest.parse(zip_file.read("META-INF/MANIFEST.MF"))

    errors = signature_manifest.verify_manifest(jar_manifest)
    if len(errors) > 0:
        msg = "%s: in .SF file, section checksum(s) failed for: %s" \
              % (jar_file, ",".join(errors))
        raise ManifestChecksumError(msg)

    # Checksums of MANIFEST.MF itself are correct.

    # Step 3: Check that it contains valid checksums for each file
    # from the JAR.  NOTE: the check is done for JAR entries. If some
    # JAR entries are deleted after signing, the verification still
    # succeeds.  This seems to not follow the reference specification,
    # but that's what jarsigner does.
    errors = jar_manifest.verify_jar_checksums(jar_file)
    if len(errors) > 0:
        msg = "Checksum(s) for jar entries of jar file %s failed for: %s" \
              % (jar_file, ",".join(errors))
        raise JarChecksumError(msg)

    return None


def sign(jar_file, cert_file, key_file,
         extra_certs=None, digest="SHA-256", output=None):
    """
    Signs the jar (almost) identically to jarsigner.
    :exception ManifestNotFoundError, CannotFindKeyTypeError
    :return None
    """

    jar = ZipFile(jar_file, "a")
    # if "META-INF/MANIFEST.MF" not in jar.namelist():
    #     raise MissingManifestError(
    #         "META-INF/MANIFEST.MF not found in %s" % jar_file)

    mf = Manifest()
    # mf.parse(jar.read("META-INF/MANIFEST.MF"))
    mf.add_jar_entries(jar_file, digest)

    # create a signature manifest, and make it match the line separator
    # style of the manifest it'll be digesting.
    sf = SignatureManifest(linesep=mf.linesep)

    sf_digest_algorithm = digest    # No point to make it different
    sf.digest_manifest(mf, sf_digest_algorithm)

    sig_digest_algorithm = digest  # No point to make it different
    sig_block_extension = private_key_type(key_file)

    sigdata = sf.get_signature(cert_file, key_file,
                               extra_certs, sig_digest_algorithm)

    # We might just add new entries to the original JAR, but jarsigner puts
    # all META-INF/ to the beginning of the archive. Let's do the same.

    with NamedTemporaryFile() as new_jar_file:
        new_jar = ZipFile(new_jar_file, "w", ZIP_STORED)
        cert_ext = "META-INF/CERT.%s" % sig_block_extension
        new_jar.writestr("META-INF/MANIFEST.MF", mf.get_data())
        new_jar.writestr("META-INF/CERT.SF", sf.get_data())
        new_jar.writestr(cert_ext, sigdata)
        exclude_files = [
            "META-INF/MANIFEST.MF",
            "META-INF/CERT.SF",
            "META-INF/BNDLTOOL.SF",
            "META-INF/BNDLTOOL.RSA",
            cert_ext
        ]
        for entry in jar.namelist():
            if entry.upper() not in exclude_files:
                new_jar.writestr(entry, jar.read(entry))

        new_jar.close()
        new_jar_file.flush()
        if output:
            return copyfile(new_jar_file.name, output)
        new_jar_file.seek(0)
        return new_jar_file.read()


def create_jar(jar_file, entries):
    """
    Create JAR from given entries.
    :param jar_file: filename of the created JAR
    :type jar_file: str
    :param entries: files to put into the JAR
    :type entries: list[str]
    :return: None
    """

    # 'jar' adds separate entries for directories, also for empty ones.
    with ZipFile(jar_file, "w") as jar:
        jar.writestr("META-INF/", "")
        jar.writestr("META-INF/MANIFEST.MF", Manifest().get_data())
        for entry in entries:
            jar.write(entry)
            if os.path.isdir(entry):
                for root, dirs, files in os.walk(entry):
                    for filename in dirs + files:
                        jar.write(os.path.join(root, filename))
