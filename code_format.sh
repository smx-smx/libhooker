#!/bin/bash
function my_indent() {
	file="$1"
	indent \
		--linux-style \
		--use-tabs \
		--tab-size4 \
		--indent-level4 \
		--preprocessor-indentation4 \
		--else-endif-column0 \
		--braces-on-if-line \
		--braces-on-func-def-line \
		--braces-on-struct-decl-line \
		--line-length0 \
			"$file"
}

if [ -z "$1" ]; then
	dirs="src include modules"
elif [ -d "$1" ]; then
	dirs="$1"
elif [ -f "$1" ]; then
	echo "Reindenting ${1}..."
	my_indent "$1"
	exit 0
fi

names=("*.c" "*.cpp" "*.h" "*.cx")
for name in "${names[@]}"; do
	if [ -z "$namearg" ]; then
		namearg="-name \"$name\""
	else
		namearg="$namearg -or -name \"$name\""
	fi
done
for file in $(eval find "$dirs" -type f "$namearg"); do
	echo "Reindenting ${file}..."
	my_indent "$file"
	chmod "$file" 644
done
exit 0
