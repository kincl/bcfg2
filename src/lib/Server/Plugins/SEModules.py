import os
import sys
import logging
import binascii
import posixpath
import lxml.etree

import Bcfg2.Server.Plugin
logger = logging.getLogger(__name__)

class SEModuleData(Bcfg2.Server.Plugin.SpecificData):
    def bind_entry(self, entry, _):
        entry.set('encoding', 'base64')
        entry.text = binascii.b2a_base64(self.data)

class SEModules(Bcfg2.Server.Plugin.GroupSpool):
    """ Handle SEModule entries """
    name = 'SEModules'
    __author__ = 'chris.a.st.pierre@gmail.com'
    es_cls = Bcfg2.Server.Plugin.EntrySet
    es_child_cls = SEModuleData
    entry_type = 'SEModule'
    experimental = True

    def HandlesEntry(self, entry, metadata):
        if entry.tag in self.Entries and entry.get("name").endswith(".pp"):
            return entry.get("name")[0:-3] in self.Entries[entry.tag]
        return Bcfg2.Server.Plugin.GroupSpool.HandlesEntry(self, entry,
                                                           metadata)

    def add_entry(self, event):
        epath = self.event_path(event)
        ident = self.event_id(event)
        if posixpath.isdir(epath):
            self.AddDirectoryMonitor(epath[len(self.data):])
        if ident not in self.entries and posixpath.isfile(epath):
            dirpath = "/".join([self.data, ident])
            basename = os.path.split(self.handles[event.requestID][:-1])[1]
            print "basename=%s" % basename
            self.entries[ident] = self.es_cls(basename,
                                              dirpath,
                                              self.es_child_cls,
                                              self.encoding)
            self.Entries[self.entry_type][ident] = \
                self.entries[ident].bind_entry
        if not posixpath.isdir(epath):
            # do not pass through directory events
            self.entries[ident].handle_event(event)

    def event_id(self, event):
        epath = self.event_path(event)
        if posixpath.isdir(epath):
            return Bcfg2.Server.Plugin.GroupSpool.event_id(self, event)
        else:
            # strip leading and trailing slashes
            return self.handles[event.requestID][1:-1]
        
