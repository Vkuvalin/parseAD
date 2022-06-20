# coding=utf-8
from active_directory_utils import (LdapEnvironmentBuilder, createAdSystemOsh, getBaseDnFromJobsParameters,
                                    LdapDaoService, AdForestDiscoverer, AdDomainDiscoverer)
from appilog.common.system.types.vectors import ObjectStateHolderVector
from appilog.common.system.types import ObjectStateHolder
import logger
import modeling


class AdObject:
    def __init__(self, dn, name=None, OSH=None, parentOSH=None):
        self.dn = dn
        self.parentOSH = parentOSH
        self.OSH = OSH
        if name == None:
            name = dn.split(',')
            name = name[0]
            self.name = name[3:]
        else:
            self.name = name


def DiscoveryMain(Framework):
    '''
    Discovery process consists of two steps:
    1. Connect domain controller and get whole topology
    2. Strive to connect to the same controller with the same credentials
        but in role of global catalog.
        2.1 GC indexes more hierarchical data but less object specific data, so
            not all data will be rediscovered.
    '''
    OSHVResult = ObjectStateHolderVector()
    ##  Destination Attribute Section
    hostId = Framework.getDestinationAttribute('hostId')
    credentialsId = Framework.getDestinationAttribute('credentials_id')
    applicationPort = Framework.getDestinationAttribute("application_port")
    serviceAddressPort = Framework.getDestinationAttribute('port')

    # Получаем порт
    if not applicationPort or applicationPort == 'NA':
        applicationPort = serviceAddressPort

    try:
        # создать клиента
        envBuilder = LdapEnvironmentBuilder(applicationPort)
        client = Framework.createClient(credentialsId, envBuilder.build())

        baseDn = getBaseDnFromJobsParameters(Framework)
        daoService = LdapDaoService(client, baseDn)

        adSystemOsh = createAdSystemOsh()
        OSHVResult.add(adSystemOsh)

        # discover forest
        forestDiscoverer = AdForestDiscoverer(daoService, adSystemOsh)
        vector = forestDiscoverer.discover()
        forestOsh = vector.get(0)
        OSHVResult.addAll(vector)

        domainDiscoverer = AdDomainDiscoverer(daoService, forestOsh)
        domainDiscoverer.discover()
        dtoToOshMap = domainDiscoverer.getResult().getMap()

        domains = []
        for (domainDto, domainOsh) in dtoToOshMap.items():
            domainName = domainOsh.getAttributeValue('data_name')
            name = domainName.split('.')
            dn = "DC={},DC={}".format(name[0], name[1])
            domainOsh.setContainer(forestOsh)
            OSHVResult.add(domainOsh)
            domains.append(AdObject(dn, name, OSH=domainOsh))

        for domain in domains:
            dirs_dns = []
            comp_dns = []
            user_dns = []

            dirs_dns.append(domain)

            categories = "(|(objectCategory=organizationalUnit)(objectCategory=computer)(objectCategory=user))"
            attrIds = ['name', 'objectCategory', 'distinguishedName']

            for ad_folder in dirs_dns:

                dir_dn = ad_folder.dn
                get_dirs = client.executeQuery(dir_dn, categories, attrIds)

                while get_dirs.next():
                    name = get_dirs.getString('name')
                    dn = get_dirs.getString('distinguishedName')
                    objCat = get_dirs.getString('objectCategory')
                    objCat = objCat.split(',')
                    objCat = objCat[0]
                    if 'Computer' in objCat:
                        comp_dns.append(AdObject(dn, name, parentOSH=ad_folder.OSH))
                    elif 'Person' in objCat:
                        user_dns.append(AdObject(dn, name, parentOSH=ad_folder.OSH))
                    elif 'CN=Organizational-Unit' in objCat:
                        tmpDirOSH = modeling.createActiveDirectoryOsh('activedirectory_ou', name)
                        tmpDirOSH.setContainer(ad_folder.OSH)
                        dirs_dns.append(AdObject(dn, name, OSH=tmpDirOSH, parentOSH=ad_folder.OSH))
                        OSHVResult.add(tmpDirOSH)

            comp_attr = ['name']
            for comp in comp_dns:
                compOSH = ObjectStateHolder('node')
                comp_data = client.getAttributes(comp.dn, comp_attr)
                while comp_data.next():
                    name = comp_data.getString('name')
                    compOSH.setAttribute('name', name)
                # compOSH.setContainer(comp.parentOSH)

                link = ObjectStateHolder('consumer_provider')
                link.setAttribute("link_end1", comp.parentOSH)
                link.setAttribute("link_end2", compOSH)
                OSHVResult.add(link)
                OSHVResult.add(compOSH)

            user_attr = ['name', 'distinguishedName', 'givenName', 'sn']
            for user in user_dns:
                userOSH = ObjectStateHolder('person')
                user_data = client.getAttributes(user.dn, user_attr)
                while user_data.next():
                    name = user_data.getString('name')
                    dn = user_data.getString('distinguishedName')

                    givenName = user_data.getString('givenName')
                    if givenName == None:
                        givenName = 'not set'

                    surname = user_data.getString('sn')
                    if surname == None:
                        surname = 'not set'

                    userOSH.setAttribute('name', name)
                    userOSH.setAttribute('distinguished_name', dn)
                    userOSH.setAttribute('given_name', givenName)
                    userOSH.setAttribute('surname', surname)

                OSHVResult.add(userOSH)
                link = ObjectStateHolder('consumer_provider')
                link.setAttribute("link_end1", user.parentOSH)
                link.setAttribute("link_end2", userOSH)
                OSHVResult.add(link)
                
    except Exception, e:
        msg = 'Failure in discovering Active Directory Topology. %s' % e
        logger.errorException(msg)
    return OSHVResult
