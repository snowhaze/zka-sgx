BEGIN {
	v = ""
}
/^SGX_[A-Z]+_VERSION_[0-9.]+/ {
	gsub(/SGX_[A-Z]+_VERSION_/, "", $0);
	if (v == "") {
		v = $0
	} else if (v != $0) {
		v = "";
		exit
	}
}
END {
	print v
}