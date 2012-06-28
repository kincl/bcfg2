import os
import copy
import selinux
import seobject
import Bcfg2.Client.XML
import Bcfg2.Client.Tools
import Bcfg2.Client.Tools.POSIX

class SELinux(Bcfg2.Client.Tools.Tool):
    """ SELinux boolean and module support """
    name = 'SELinux'
    __handles__ = [('SELinux', 'boolean'),
                   ('SELinux', 'port'),
                   ('SELinux', 'fcontext'),
                   ('SELinux', 'node'),
                   ('SELinux', 'login'),
                   ('SELinux', 'user'),
                   ('SELinux', 'interface'),
                   ('SELinux', 'permissive'),
                   ('SELinux', 'module')]
    __req__ = {'SELinux': {
        'boolean': ['name', 'value'],
        'module': ['name', '__text__'],
        'port': ['name', 'selinuxtype', 'proto'],
        'fcontext': ['name', 'selinuxtype'],
        'node': ['name', 'selinuxtype', 'proto'],
        'login': ['name', 'selinuxuser'],
        'user': ['name'],
        'interface': ['name', 'selinuxtype'],
        'permissive': ['name'],}}

    def __init__(self, logger, setup, config):
        Bcfg2.Client.Tools.Tool.__init__(self, logger, setup, config)
        self.handlers = {}
        for handles in self.__handles__:
            etype = handles[1]
            self.handlers[etype] = \
                globals()["SELinux%sHandler" % etype.title()](self, logger,
                                                              setup, config)

    def BundleUpdated(self, _, states):
        for handler in self.handlers.values():
            handler.BundleUpdated(states)

    def FindExtra(self):
        extra = []
        for handler in self.handlers.values():
            extra.extend(handler.FindExtra())
        return extra

    def canInstall(self, entry):
        return (Bcfg2.Client.Tools.Tool.canInstall(self, entry) and
                self.handler[entry.get('type')].canInstall(entry))

    def InstallSELinux(self, entry):
        """Dispatch install to the proper method according to type"""
        return self.handler[entry.get('type')].Install(entry)

    def VerifySELinux(self, entry, _):
        """Dispatch verify to the proper method according to type"""
        rv = self.handler[entry.get('type')].Verify(entry)
        if entry.get('qtext') and self.setup['interactive']:
            entry.set('qtext',
                      '%s\nInstall SELinux %s %s: (y/N) ' %
                      (entry.get('qtext'),
                       entry.get('type'),
                       self.handler[entry.get('type')].tostring(entry)))
        return rv

    def Remove(self, entries):
        """Dispatch verify to the proper removal method according to type"""
        # sort by type
        types = list()
        for entry in entries:
            if entry.get('type') not in types:
                types.append(entry.get('type'))

        for etype in types:
            self.handler[entry.get('type')].Remove([e for e in entries
                                                    if e.get('type') == etype])
        
class SELinuxEntryHandler(object):
    etype = None
    key_format = ("name")
    value_format = ()
    str_format = '%(name)'
    
    def __init__(self, tool, logger, setup, config):
        self.tool = tool
        self.logger = logger
        self._records = None
        self._all = None

    @property
    def records(self):
        if self._records is None:
            self._records = getattr(seobject, "%sRecords" % self.etype)("")
        return self._records

    @property
    def all_records(self):
        if self._all is None:
            self._all = self.records.get_all()
        return self._all

    def tostring(self, entry):
        return self.str_format % self._entry2attrs(entry)

    def keytostring(self, key):
        return self.str_format % self._key2attrs(key)

    def _key(self, entry):
        rv = []
        for key in self.key_format:
            rv.append(entry.get(key))
        return tuple(rv)

    def _key2attrs(self, key):
        if isinstance(key, tuple):
            rv = dict((self.key_format[i], key[i])
                      for i in range(len(self.key_format))
                      if self.key_format[i])
        else:
            rv = dict(name=key)
        if self.value_format == "selinuxtype":
            rv["selinuxtype"] = ":".join(self.all_records[key])
        elif self.value_format:
            vals = self.all_records[key]
            rv.update(dict((self.value_format[i], vals[i])
                           for i in range(len(self.value_format))
                           if self.value_format[i]))
        return rv

    def _entry2attrs(self, entry):
        vals = self._key(entry)
        return dict([(key, vals[key]) for key in self.key_format])

    def key2entry(self, key):
        attrs = self._key2attrs(key)
        attrs["type"] = self.etype
        return Bcfg2.Client.XML.Element("SELinux", **attrs)

    def _installargs(self, entry):
        raise NotImplementedError

    def _deleteargs(self, entry):
        return (self._key(entry))

    def _expected(self):
        raise NotImplementedError

    def canInstall(self, entry):
        return True
    
    def exists(self, entry):
        if self._key(entry) not in self.all_records:
            self.logger.debug("SELinux %s %s does not exist" %
                              (self.etype, self.tostring(entry)))
            return False
        return True

    def _verify_attr(self, entry, record, key, attr, value):
        return value == self.get(attr)
    
    def Verify(self, entry):
        if not self.exists(entry):
            entry.set('current_exists', 'false')
            return False

        errors = []
        expected = self._expected(self)
        key = self._key(entry)
        record = self.all_records[key]
        for idx in range(0, len(expected)):
            attr = expected[idx]
            if not attr:
                continue
            current = record[idx]
            if not self._verify_attr(entry, record, key, attr, current):
                entry.set('current_%s' % attr, current)
                errors.append("SELinux %s %s has wrong %s: %s, should be %s" %
                              (self.etype, self.tostring(entry), attr,
                               current, desired))

        if errors:
            for error in errors:
                self.logger.debug(msg)
            entry.set('qtext', "\n".join([entry.get('qtext', '')] + errors))
            return False
        else:
            return True

    def Install(self, entry):
        if self.exists(entry):
            self.logger.debug("Modifying SELinux %s %s" %
                              (self.etype, self.tostring(entry)))
            method = "modify"
        else:
            self.logger.debug("Adding non-existent SELinux %s %s" %
                              (self.etype, self.tostring(entry)))
            method = "add"

        try:
            getattr(self.records, method)(*self._installargs(entry))
            self._all = None
            return True
        except ValueError:
            err = sys.exc_info()[1]
            self.logger.debug("Failed to %s SELinux %s %s: %s" %
                              (method, self.etype, self.tostring(entry), err))
            return False

    def Remove(self, entries):
        for entry in entries:
            try:
                self.records.delete(*self._deleteargs(entry))
                self._all = None
            except ValueError:
                err = sys.exc_info()[1]
                self.logger.info("Failed to remove SELinux %s %s: %s" %
                                 (self.etype, self.tostring(entry), err))

    def FindExtra(self):
        specified = [self._key(e)
                     for e in self.tool.getSupportedEntries()
                     if e.type == self.etype]
        return [self.key2entry(key)
                for key in self.all_records.keys()
                if key not in specified]

    def BundleUpdated(self, states):
        pass


class SELinuxBooleanHandler(SELinuxEntryHandler):
    etype = "boolean"

    def _verify_attr(self, entry, record, key, attr, value):
        return ((value and entry.get("attr") == "on") or
                (not value and entry.get("attr") == "off"))

    def _key2attrs(self, key):
        rv = SELinuxEntryHandler._key2attrs(self, key)
        status = self.all_records[key][0]
        if status:
            rv['value'] = "on"
        else:
            rv['value'] = "off"
        return rv

    def canInstall(self, entry):
        return self.exists(entry)
    
    def _expected(self):
        return ("value", None, None)
    
    def Install(self, entry):
        boolean = entry.get("name")
        # we do this using the non-OO interface (selinux instead of
        # seobject) because it supports transactions even in older
        # versions.  the seobject interface only supports transactions
        # in recent versions
        rv = selinux.security_set_boolean(boolean, bool(entry.get("value")))
        if rv == -1:
            self.logger.debug("Error setting value of SELinux boolean %s" %
                              boolean)
            return False
        elif bool(rv):
            self.booleans_changed = True
        return bool(rv)

    def BundleUpdated(self, _, states):
        if self.booleans_changed:
            # commit boolean changes
            selinux.security_commit_booleans()


class SELinuxPortHandler(SELinuxEntryHandler):
    etype = "port"
    str_format = '%(name)/%(proto)'
    value_format = ('selinuxtype', None)
    
    @property
    def all_records(self):
        if self._all is None:
            # older versions of selinux use (startport, endport) as
            # they key for the ports.get_all() dict, and (type, proto,
            # level) as the value; this is obviously broken, so newer
            # versions use (startport, endport, proto) as the key, and
            # (type, level) as the value.  abstracting around this
            # sucks.
            ports = self.records.get_all()
            if len(ports.keys()[0]) == 3:
                self._all = ports
            else:
                # uglist list comprehension ever?
                self._all = dict([((k[0], k[1], v[1]), (v[0], v[2]))
                                  for k, v in ports.items()])
        return self._all

    def _key(self, entry):
        port = entry.get("name")
        if ":" in port:
            start, end = port.split(":")
        else:
            start = port
            end = port
        return (start, end, self.get("proto"))
    
    def _key2attrs(self, key):
        if key[0] == key[1]:
            port = str(key[0])
        else:
            port = "%s:%s" % (key[0], key[1])
        vals = self.all_records[key]
        return dict(name=port, proto=key[2], selinuxtype=vals[0])

    def _entry2attrs(self, entry):
        return dict(name=entry.get("name"), proto=entry.get("proto"))

    def _expected(self):
        return ("selinuxtype", None)

    def _installargs(self, entry):
        return (entry.get("name"), entry.get("proto"), '',
                entry.get("selinuxtype"))

    def _deleteargs(self, entry):
        return (entry.get("name"), entry.get("proto"))


class SELinuxFcontextHandler(SELinuxEntryHandler):
    etype = "fcontext"
    key_format = ("name", "filetype")
    value_format = "selinuxtype"
    filetypeargs = dict(all="",
                        regular="--",
                        directory="-d",
                        symlink="-l",
                        pipe="-p",
                        socket="-s",
                        block="-b",
                        char="-c",
                        door="-D")
    filetypenames = dict(all="all files",
                        regular="regular file",
                        directory="directory",
                        symlink="symbolic link",
                        pipe="named pipe",
                        socket="socket",
                        block="block device",
                        char="character device",
                        door="door")
    filetypeattrs = dict([v, k] for k, v in filetypenames.iteritems())

    @property
    def all_records(self):
        if self._all is None:
            # on older selinux, fcontextRecords.get_all() returns a
            # list of tuples of (filespec, filetype, seuser, serole,
            # setype, level); on newer selinux, get_all() returns a
            # dict of (filespec, filetype) => (seuser, serole, setype,
            # level).
            fcontexts = self.records.get_all()
            if isinstance(fcontexts, dict):
                self._all = fcontexts
            else:
                self._all = dict([(f[0:2], f[2:]) for f in fcontexts])
        return self._all

    def _key(self, entry):
        return (entry.get("name"),
                self.filetypenames[entry.get("filetype", "all")])

    def _key2attrs(self, key):
        rv = dict(name=key[0], filetype=self.filetypeattrs[key[1]])
        vals = self.all_records[key]
        if vals:
            rv["selinuxtype"] = ":".join(self.all_records[key])
        else:
            rv["selinuxtype"] = "<<none>>"
        return rv

    def _expected(self):
        return (None, None, "selinuxtype", None)

    def _installargs(self, entry):
        return (entry.get("name"), entry.get("selinuxtype"),
                self.filetypeargs[entry.get("filetype", "all")],
                '', '')
        

class SELinuxNodeHandler(SELinuxEntryHandler):
    etype = "node"
    key_format = ("name", "netmask", "proto")
    value_format = "selinuxtype"
    str_format = '%(name)/%(netmask) (%(proto))'

    def _expected(self):
        return (None, None, "selinuxtype", None)

    def _installargs(self, entry):
        return (entry.get("name"), entry.get("netmask"),
                entry.get("proto"), "", entry.get("selinuxtype"))


class SELinuxLoginHandler(SELinuxEntryHandler):
    etype = "login"
    value_format = ("selinuxuser", None)

    def _expected(self):
        return ("selinuxuser", None)
    
    def _installargs(self, entry):
        return (entry.get("name"), entry.get("selinuxuser"), "")


class SELinuxUserHandler(SELinuxEntryHandler):
    etype = "user"
    value_format = ("prefix", None, None, "roles")

    @property
    def records(self):
        if self._records is None:
            self._records = seobject.seluserRecords()
        return self._records

    def _expected(self):
        return ("prefix", None, None, "roles")
    
    def _installargs(self, entry):
        roles = entry.get("roles", "").replace(" ", ",").split(",")
        return (entry.get("name"), roles, '', '', entry.get("prefix"))


class SELinuxInterfaceHandler(SELinuxEntryHandler):
    etype = "interface"
    value_format = "selinuxtype"

    def _installargs(self, entry):
        return (entry.get("name"), '', entry.get("selinuxtype"))

    def _expected(self):
        return (None, None, entry.get("selinuxtype"), None)


class SELinuxPermissiveHandler(SELinuxEntryHandler):
    etype = "permissive"
    
    @property
    def records(self):
        try:
            return SELinuxEntryHandler.records.fget(self)
        except AttributeError:
            self.logger.info("Permissive domains not supported by this version "
                             "of SELinux")
            self._records = False
            return self._records

    @property
    def all_records(self):
        if self._all is None:
            if self.records == False:
                self._all = dict()
            else:
                # permissiveRecords.get_all() returns a list, so we just
                # make it into a dict so that the rest of
                # SELinuxEntryHandler works
                self._all = dict([(d, d) for d in self.records.get_all()])
        return self._all

    def _installargs(self, entry):
        return (entry.get("name"))


class SELinuxModuleHandler(SELinuxEntryHandler):
    etype = "module"

    def __init__(self, tool, logger, setup, config):
        SELinuxEntryHandler.__init__(self, tool, logger, setup, config)
        self.posixtool = Bcfg2.Client.Tools.POSIX.POSIX(logger, setup, config)

    @property
    def all_records(self):
        if self._all is None:
            # we get a list of tuples back; coerce it into a dict
            self._all = dict([(m[0], (m[1], m[2]))
                             for m in self.records.get_all()])
        return self._all

    def _expected(self):
        return (None, "disabled")

    def _filepath(self, entry):
        if entry.get("name").endswith(".pp"):
            # the .pp is optional in Bundler
            filename = entry.get("name")
        else:
            filename = "%s.pp" % entry.get("name")
        return os.path.join("/usr/share/selinux", selinux_mode(), filename)

    def _pathentry(self, entry):
        pathentry = copy.copy(entry)
        pathentry.set("path", self._filepath(entry))
        pathentry.set("perms", "0644")
        pathentry.set("owner", "root")
        pathentry.set("group", "root")
        pathentry.set("secontext", "__default__")
        return pathentry

    def Verify(self, entry):
        rv = SELinuxEntryHandler.Verify(self, entry)
        rv &= self.posixtool.Verifyfile(self._pathentry(entry), None)
        return rv

    def Install(self, entry):
        return (self.posixtool.Installfile(self._pathentry(entry)) and
                SELinuxEntryHandler.Install(self, entry))

    def _installargs(self, entry):
        return (self._filepath(entry))

    def _deleteargs(self, entry):
        return (entry.get("name").replace(".pp", ""))

    def FindExtra(self):
        # do not inventory selinux modules; it'd be basically
        # impossible to keep a full inventory of modules on the Bcfg2
        # server, and we probably don't want to anyway
        return []
