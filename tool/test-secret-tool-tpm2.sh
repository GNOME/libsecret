#!/bin/sh

set -e

testdir=$PWD/test-secret-tool-tpm2-$$
test -d "$testdir" || mkdir "$testdir"

cleanup () {
	rm -rf "$testdir"
}
trap cleanup 0

cd "$testdir"

SECRET_BACKEND=file
export SECRET_BACKEND

SECRET_FILE_TEST_PATH=$testdir/keyring
export SECRET_FILE_TEST_PATH

: ${SECRET_TOOL="$abs_top_builddir"/tool/secret-tool}

: ${DIFF=diff}

echo 1..6

echo test1 | ${SECRET_TOOL} store --label label1 foo bar
if test $? -eq 0; then
  echo "ok 1 /secret-tool/store1"
else
  echo "not ok 1 /secret-tool/store1"
fi

echo test2 | ${SECRET_TOOL} store --label label2 foo bar apple orange
if test $? -eq 0; then
  echo "ok 2 /secret-tool/store2"
else
  echo "not ok 2 /secret-tool/store2"
fi

echo test1 > lookup.exp
${SECRET_TOOL} lookup foo bar > lookup.out
if ${DIFF} lookup.exp lookup.out > lookup.diff; then
  echo "ok 3 /secret-tool/lookup"
else
  echo "not ok 3 /secret-tool/lookup"
  sed 's/^/# /' lookup.diff
  exit 1
fi

cat > search.exp <<EOF
[no path]
label = label1
secret = test1

[no path]
label = label2
secret = test2

EOF

${SECRET_TOOL} search foo bar | sed '/^created\|^modified/d' > search.out
if test $? -ne 0; then
  echo "not ok 4 /secret-tool/search"
  exit 1
fi
if ${DIFF} search.exp search.out > search.diff; then
  echo "ok 4 /secret-tool/search"
else
  echo "not ok 4 /secret-tool/search"
  sed 's/^/# /' search.diff
  exit 1
fi

${SECRET_TOOL} clear apple orange
if test $? -eq 0; then
  echo "ok 5 /secret-tool/clear"
else
  echo "not ok 5 /secret-tool/clear"
  exit 1
fi

cat > search-after-clear.exp <<EOF
[no path]
label = label1
secret = test1

EOF

${SECRET_TOOL} search foo bar | sed '/^created\|^modified/d' > search-after-clear.out
if test $? -ne 0; then
  echo "not ok 6 /secret-tool/search-after-clear"
  exit 1
fi
if ${DIFF} search-after-clear.exp search-after-clear.out > search-after-clear.diff; then
  echo "ok 6 /secret-tool/search-after-clear"
else
  echo "not ok 6 /secret-tool/search-after-clear"
  sed 's/^/# /' search-after-clear.diff
  exit 1
fi
