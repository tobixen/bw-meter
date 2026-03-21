# Bandwith Metering Project

CLI-tool for digging into accumulated bandwidth statistics

## Rationale

I'm most of the time using mobile networks for my internet connectivity, and then most of the time I have a metered connection.  For my primary subscription, it's full stop if the monthly limit is exceeded - and full stop means disaster.

## Existing systems

I did have a look through existing systems a while ago, and found many network monitoring tools, but nothing that was immediately useful for me.  The existing tools often has a wrong focus:

* Sorting/grouping activity by the remote IP address.  Fine, that's useful, but not enough, I want:
  - ability to sort by PID
  - ability to sort by process name
  - ability to sort by process group and/or systemd unit
  - ability to sort by hostname.  Nowadays an RDNS-lookup is most often useless.  The hostname we're connecting to can be found by inspecting the DNS lookup traffic.
* Monitoring activity *right now*.  That's useful if you wonder if there is a sudden traffic spike right now - however, to get an overview of "spending", making it possible to do future "budgeting", it's needed with accumulated numbers for a longer time period.

## Design

See the [DESIGN.md](DESIGN.md) file
