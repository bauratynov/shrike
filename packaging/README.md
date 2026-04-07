# shrike packaging

Three packaging modes, each intentionally minimal.

## Docker (scratch image, ~900 KB)

```bash
docker build -f packaging/Dockerfile -t shrike:0.28.0 .
docker run --rm -v /bin:/host shrike:0.28.0 --quiet /host/ls
```

## Debian

```bash
ln -s packaging/debian .
dpkg-buildpackage -us -uc
```

Produces `shrike_0.28.0_amd64.deb` with `/usr/bin/shrike`.

## RPM

```bash
rpmbuild -ba packaging/shrike.spec
```

## Homebrew (formula pending)

A formula for `brew install shrike` is tracked for v0.29.

## Tarball release (minisign-signed)

Release tarballs are signed with minisign. Public key:

```
untrusted comment: minisign public key (shrike)
<TBD at v1.0.0>
```
