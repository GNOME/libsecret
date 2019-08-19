#!/bin/sh

set -e

testdir=$PWD/test-secret-tool-$$
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

SECRET_FILE_TEST_PASSWORD=test
export SECRET_FILE_TEST_PASSWORD

: ${DIFF=diff}

echo 1..4

echo test1 | "$abs_top_builddir"/tool/secret-tool store --label label1 foo bar
if test $? -eq 0; then
  echo "ok 1 /secret-tool/store"
else
  echo "not ok 1 /secret-tool/store"
fi

echo test2 | "$abs_top_builddir"/tool/secret-tool store --label label2 foo bar apple orange
if test $? -eq 0; then
  echo "ok 1 /secret-tool/store"
else
  echo "not ok 1 /secret-tool/store"
fi

echo test1 > lookup.exp
"$abs_top_builddir"/tool/secret-tool lookup foo bar > lookup.out
if ${DIFF} lookup.exp lookup.out > lookup.diff; then
  echo "ok 2 /secret-tool/lookup"
else
  echo "not ok 2 /secret-tool/lookup"
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

"$abs_top_builddir"/tool/secret-tool search foo bar | sed '/^created\|^modified/d' > search.out
if test $? -ne 0; then
  echo "not ok 3 /secret-tool/search"
  exit 1
fi
if ${DIFF} search.exp search.out > search.diff; then
  echo "ok 3 /secret-tool/search"
else
  echo "not ok 3 /secret-tool/search"
  sed 's/^/# /' search.diff
  exit 1
fi

"$abs_top_builddir"/tool/secret-tool clear apple orange
if test $? -eq 0; then
  echo "ok 4 /secret-tool/clear"
else
  echo "not ok 4 /secret-tool/clear"
  exit 1
fi

cat > search-after-clear.exp <<EOF
[no path]
label = label1
secret = test1

EOF

"$abs_top_builddir"/tool/secret-tool search foo bar | sed '/^created\|^modified/d' > search-after-clear.out
if test $? -ne 0; then
  echo "not ok 5 /secret-tool/search-after-clear"
  exit 1
fi
if ${DIFF} search-after-clear.exp search-after-clear.out > search-after-clear.diff; then
  echo "ok 5 /secret-tool/search-after-clear"
else
  echo "not ok 5 /secret-tool/search-after-clear"
  sed 's/^/# /' search-after-clear.diff
  exit 1
fi
