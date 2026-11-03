#!/usr/bin/env bash
# build-deb.sh: compila o accel-ppp-ng com o módulo vyos_vpp e gera o .deb via CPack.
#
# Requer o VPP instalado pelos .deb do adv-vpp (vpp-dev e libvppinfra-dev),
# porque o vyos_vpp linka em vppapiclient, vapiclient, vlibapi e vlib.
#
# Variáveis de ambiente:
#   CPACK_TYPE  perfil de dependências do cmake/cpack.cmake (padrão: Debian13)
#   BUILD_DIR   diretório de build, apagado a cada execução (padrão: build/deb)
#   JOBS        paralelismo do make (padrão: nproc)
set -euo pipefail

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CPACK_TYPE=${CPACK_TYPE:-Debian13}
BUILD_DIR=${BUILD_DIR:-$SRC/build/deb}
JOBS=${JOBS:-$(nproc)}

die() { echo "build-deb: $*" >&2; exit 1; }

for pkg in vpp-dev libvppinfra-dev; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' ||
        die "pacote $pkg não instalado (instale os .deb do adv-vpp antes)"
done

# Versão do pacote no mesmo formato dos .deb do adv-vpp:
#   <base>-<commits>~adv<data UTC do build>.<hash>[.dirty]
# A base é a versão fixa do CMakeLists.txt (o repositório não tem tags), o
# número de commits ordena builds de commits diferentes e a data ordena builds
# repetidos do mesmo commit. ".dirty" marca alterações não commitadas.
base=$(sed -n 's/^[[:space:]]*SET (ACCEL_PPP_VERSION \([0-9.]*\))$/\1/p' "$SRC/CMakeLists.txt")
[[ -n $base ]] || die "versão base não encontrada no CMakeLists.txt"
git -C "$SRC" update-index -q --refresh || true
dirty=""
git -C "$SRC" diff-index --quiet HEAD -- || dirty=".dirty"
VERSION="$base-$(git -C "$SRC" rev-list --count HEAD)~adv$(date -u +%Y%m%d%H%M%S).$(git -C "$SRC" rev-parse --short HEAD)$dirty"

# Build limpo: um cache antigo levaria opções de outro configure para o pacote.
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake \
    -DCPACK_TYPE="${CPACK_TYPE}" \
    -DRADIUS=TRUE \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_DRIVER=FALSE \
    -DHAVE_VPP=1 \
    -DHAVE_SESSION_HOOKS=1 \
    -DCPACK_DEBIAN_PACKAGE_VERSION="$VERSION" \
    "$SRC"

make -j"$JOBS"
cpack -G DEB

# O debian.cmake gera o arquivo só com o nome do pacote (accel-ppp-ng.deb);
# renomeia para o padrão do Debian a partir dos campos do próprio pacote.
deb=$BUILD_DIR/accel-ppp-ng.deb
[[ -f $deb ]] || die "cpack não gerou $deb"
name=$(dpkg-deb -f "$deb" Package)_$(dpkg-deb -f "$deb" Version)_$(dpkg-deb -f "$deb" Architecture).deb
mv "$deb" "$BUILD_DIR/$name"

echo "build-deb: $BUILD_DIR/$name"
