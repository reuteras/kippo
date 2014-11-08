# -*- coding: utf-8 -*-
# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information

from kippo.core.honeypot import HoneyPotCommand

commands = {}

class command_which(HoneyPotCommand):

    def call(self):
        if not len(self.args):
            return

        for cmd in self.args:
            for path in '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games'.split(':'):
                resolved = self.honeypot.fs.resolve_path(cmd, path)
                if self.honeypot.fs.exists(resolved):
                    self.honeypot.writeln("%s/%s" % (path, cmd))
                    continue

commands['/bin/which'] = command_which

# vim: set sw=4 et:
