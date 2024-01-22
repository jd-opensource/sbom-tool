module github.com/group0/art0

go 1.18

require golang.org/x/net v1.2.1

require (
    golang.org/x/crypto v1.4.5 // indirect
    golang.org/x/text v1.6.7
)

replace golang.org/x/net v1.2.3 => example.com/fork/net v1.4.5
replace (
    golang.org/x/net v1.2.4 => example.com/fork/net v1.4.5
    golang.org/x/net => example.com/fork/net v1.4.5
    golang.org/x/net v1.2.5 => ./fork/net
    golang.org/x/net => ./fork/net
)

exclude golang.org/x/net v1.2.3

exclude (
    golang.org/x/crypto v1.4.5
    golang.org/x/text v1.6.7
)