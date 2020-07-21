BEGIN {
	n = 0;
	h = "";
}
{
	if (n == 1 && h == "") {
		h = x ;
		n--
	} else if (n == 1 && h == x) {
		n--
	} else if (n ==1) {
		h = "";
		exit
	} else if (n > 0) {
		n--;
		x = x$0;
		gsub(/ |0x/, "", x)
	}
}
$0 == "metadata->enclave_css.body.enclave_hash.m:" {
	n = 3;
	x = ""
}
END {
	print h
}