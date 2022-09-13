# $1 - user
# $2 - passwd
function do_passwd {
expect <<EOF
set timeout 5
spawn -noecho passwd $1
expect_after {
    timeout {exit 2}
    eof {exit 1}
}
expect {
    -nocase "new*" { puts "$2"; send -- "$2\r"}
}
expect {
    -nocase "retype*" { puts "$2"; send -- "$2\r"}
}
expect {
    -nocase "passwd: all authentication tokens updated successfully." { exit 0}
    -nocase "passwd: Have exhausted maximum number of retries for service" { exit 3}
}
expect eof
exit 2
EOF
}

do_passwd $1 $2