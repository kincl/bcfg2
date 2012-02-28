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
                locals()["SELinux%sHandler" % etype.title()]()

    def BundleUpdated(self, _, states):
        for handler in self.handlers.values():
            handler.BundleUpdated(states)

    def FindExtra(self):
        return [h.FindExtra() for h in self.handlers.values()]

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
    self.etype = None
    
    def __init__(self):
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
        return self.get("name")

    def _key(self, entry):
        return self.get("name")

    def _namefromkey(self, key):
        if isinstance(key, tuple):
            return key[0]
        else:
            return key

    def _installargs(self, entry):
        return ()

    def _deleteargs(self, entry):
        return (self._key(entry))

    def _expected(self):
        return ()

    def canInstall(self, entry):
        return True
    
    def exists(self, entry):
        if self._key(entry) not in self.all_records:
            self.logger.debug("SELinux %s %s does not exist" %
                              (self.etype, self.tostring(entry)))
            return False
        return True
    
    def Verify(self, entry):
        if not self.exists():
            entry.set('current_exists', 'false')
            return False

        errors = []
        expected = self._expected(self)
        record = self.all_records[self._key(entry)]
        for idx in range(0, len(expected)):
            attr = expected[idx]
            current = record[idx]
            desired = self.get(attr)
            if desired and current != desired:
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
            getattr(ports, method)(*self._installargs(entry))
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
                                 (self.etype, entry.get('name'), err))

    def FindExtra(self):
        self.logger.debug("Found SELinux %ss:" % self.etype)
        self.logger.debug(self.all_records.keys())
        specified = [e.get('name')
                     for e in self.getSupportedEntries()
                     if e.type == self.etype]
        return [Bcfg2.Client.XML.Element('SELinux',
                                         type=self.etype,
                                         name=name)
                for name in self.all_records.keys()
                if name not in specified]

    def BundleUpdated(self, states):
        pass


class SELinuxBooleanHandler(SELinuxEntryHandler):
    etype = "boolean"

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

    def tostring(self, entry):
        return "%s/%s" % (entry.get('name'), entry.get('proto'))

    def _expected(self):
        return ("selinuxtype", None)

    def _installargs(self, entry):
        return (entry.get("name"), entry.get("proto"), '',
                entry.get("selinuxtype"))

    def _deleteargs(self, entry):
        return (entry.get("name"), entry.get("proto"))


class SELinuxFcontextHandler(SELinuxEntryHandler):
    etype = "fcontext"
    filetypemap = dict(all="",
                       regular="--",
                       directory="-d",
                       symlink="-l",
                       pipe="-p",
                       socket="-s",
                       block="-b",
                       char="-c",
                       door="-D")

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
        ftype = self.get("filetype")
        if ftype == None:
            ftype = "all files"
        elif ftype == "regular":
            ftype = "regular file"
        elif ftype == "symlink":
            ftype = "symbolic link"
        elif ftype == "pipe":
            ftype = "named pipe"
        elif ftype == "block":
            ftype = "block device"
        elif ftype == "char":
            ftype = "character device"
        return (self.get("name"), ftype)

    def _expected(self):
        return (None, None, "selinuxtype", None)

    def _installargs(self, entry):
        return (entry.get("name"), entry.get("selinuxtype"),
                self.filetypemap(entry.get("filetype", "all")),
                '', '')
        

class SELinuxNodeHandler(SELinuxEntryHandler):
    etype = "node"

    def _key(self, entry):
        return (entry.get("name"), entry.get("netmask"), entry.get("proto"))

    def _expected(self):
        return (None, None, "selinuxtype", None)

    def _installargs(self, entry):
        return (entry.get("name"), entry.get("netmask"),
                entry.get("proto"), "", entry.get("selinuxtype"))


class SELinuxLoginHandler(SELinuxEntryHandler):
    etype = "login"

    def _expected(self):
        return ("selinuxuser", None)
    
    def _installargs(self, entry):
        return (self.get("name"), self.get("selinuxuser"), "")


class SELinuxUserHandler(SELinuxEntryHandler):
    etype = "user"

    @property
    def records(self):
        if self._records is None:
            self._records = seobject.seluserRecords()
        return self._records

    def _expected(self):
        return ("prefix", None, None, "roles")
    
    def _installargs(self, entry):
        return (self.get("name"), roles, '', '', self.get("prefix"))


class SELinuxInterfaceHandler(SELinuxEntryHandler):
    etype = "interface"

    def _installargs(self, entry):
        return (self.get("name"), '', self.get("selinuxtype"))

    def _expected(self):
        return (None, None, self.get("selinuxtype"), None)


class SELinuxPermissiveHandler(SELinuxEntryHandler):
    etype = "permissive"
    
    @property
    def records(self):
        try:
            return SELinuxEntryHandler.records(self)
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
            # permissionRecords.get_all() returns a list, so we just
            # make it into a dict so that the rest of
            # SELinuxEntryHandler works
            self._all = dict([(d, d) for d in self.records.get_all()])
        return self._all

    def _installargs(self, entry):
        return (self.get("name"))


class SELinuxModuleHandler(SELinuxEntryHandler):
    def __init__(self, logger, setup, config):
        SELinuxEntryHandler.__init__(self, logger, setup, config)
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
        return (self.get("name").replace(".pp", ""))

    def FindExtra(self):
        # do not inventory selinux modules; it'd be basically
        # impossible to keep a full inventory of modules on the Bcfg2
        # server, and we probably don't want to anyway
        return []
