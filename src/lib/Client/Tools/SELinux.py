import selinux
import Bcfg2.Client.XML
import Bcfg2.Client.Tools

class SELinux(Bcfg2.Client.Tools.Tool):
    """ SELinux boolean and module support """
    name = 'SELinux'
    __handles__ = [('SEBoolean', None),
                   ('SEModule',  None)]
    __req__ = {'SEBoolean': ['name', 'value'],
               'SEModule': ['name']}

    def canInstall(self, entry):
        if Bcfg2.Client.Tools.Tool.canInstall(self, entry):
            if entry.tag == "SEBoolean":
                boolean = entry.get("name")
                if boolean not in selinux.security_get_boolean_names():
                    self.logger.debug("SELinux boolean %s does not exist" %
                                      boolean)
                    return False
            return True
        else:
            return False

    def BundleUpdated(self, _, states):
        if self.booleans_changed:
            # commit boolean changes
            selinux.security_commit_booleans()

    def VerifySEBoolean(self, entry, _):
        boolean = entry.get("name")
        if boolean not in selinux.security_get_boolean_names():
            self.logger.debug("SELinux boolean %s does not exist" %
                              boolean)
            return False

        setting = selinux.security_get_boolean_active(boolean)
        if setting == -1:
            self.logger.debug("Error getting value of SELinux boolean %s" %
                              boolean)
            return False
        elif bool(setting) == (entry.get("value").lower() == 'true'):
            # this condition is a clever/ugly way of saying:
            # * if setting is 1 (True) and the desired value is true; or
            # * if setting is 0 (False) and the desired value is false
            return True
        else:
            msg = "SELinux boolean %s is set improperly: %s" % bool(setting)
            self.logger.debug(msg)
            entry.set("current_value", str(setting))
            entry.set("qtext",
                      "%s\nSet value to %s? [y/N] " % (msg, entry.get("value")))
            return False

    def InstallSEBoolean(self, entry):
        boolean = entry.get("name")
        rv = selinux.security_set_boolean(boolean, bool(entry.get("value")))
        if rv == -1:
            self.logger.debug("Error setting value of SELinux boolean %s" %
                              boolean)
            return False
        elif bool(rv):
            self.booleans_changed = True
        return bool(rv)

    def FindExtra(self):
        allbool = selinux.security_get_boolean_names()
        self.logger.debug("Found SELinux booleans:")
        self.logger.debug(allbool)
        specified = [e.get('name')
                     for e in self.getSupportedEntries()
                     if e.tag == 'SEBoolean']
        return [Bcfg2.Client.XML.Element('SEBoolean',
                                         name=name)
                for name in allbool
                if name not in specified]
