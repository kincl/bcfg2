import sys
import binascii
import logging
import lxml.etree

import Bcfg2.Server.Plugin
logger = logging.getLogger(__name__)

class SEModuleEntrySet(Bcfg2.Server.Plugin.EntrySet):
    def bind_entry(self, entry, metadata):
        Bcfg2.Server.Plugin.EntrySet.bind_entry(self, entry, metadata)
        entry.set('encoding', 'base64')
        entry.text = binascii.b2a_base64(entry.text)

class SEModules(Bcfg2.Server.Plugin.GroupSpool):
    """ Handle SEModule entries """
    name = 'SEModules'
    __author__ = 'chris.a.st.pierre@gmail.com'
    es_cls = SEModuleEntrySet
    es_child_cls = Bcfg2.Server.Plugin.SpecificData
    entry_type = 'SEModule'

    def HandlesEntry(self, entry, metadata):
        if entry.tag in self.Entries and entry.get("name").endswith(".pp"):
            return entry.get("name")[0:-3] in self.Entries[entry.tag]
        return Bcfg2.Server.Plugin.GroupSpool.HandlesEntry(self, entry,
                                                           metadata)
