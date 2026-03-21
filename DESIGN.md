TODO - write a design document here.

My basic idea is to have a systemd unit collecting statistics (possibly using ptcpdump) and store accumulated statistics somewhere.  Have a CLI tool for digging into the data.

Perhaps a sqlite database designed after data warehouse principles could be an idea.  Perhaps store (bytes transferred, direction, start timestamp, interval length, remote host by captured DNS lookup, remote IP, remote port, protocol, PID, more process information, something else?) for fixed intervals (configurable, but with some default ... 10 minutes? 1 minute?)  Or perhaps KISS, just store things in json files.

How much overhead is it having ptcpdump running?  It's a question if the service should run all the time, or if the service should be started and stopped only when the user wants to check up things.

The CLI should allow quite some digging, not only to find the total metering, but also to drill down on suspicious activity.
