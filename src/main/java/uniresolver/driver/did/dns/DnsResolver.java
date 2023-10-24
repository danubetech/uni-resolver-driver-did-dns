package uniresolver.driver.did.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import uniresolver.ResolutionException;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class DnsResolver {

    private static Logger log = LoggerFactory.getLogger(DnsResolver.class);

    private String dnsServers;
    private Resolver resolver;

    public DnsResolver(String dnsServers) {
        this.dnsServers = dnsServers;
    }

    public void init() throws ResolutionException {
        try {
            if (this.getDnsServers() != null && !this.getDnsServers().trim().isEmpty()) {
                String[] dnsServers = this.getDnsServers().split(";");
                this.setResolver(new ExtendedResolver(dnsServers));
                if (log.isInfoEnabled())
                    log.info("Created DNS resolver with servers " + Arrays.asList(dnsServers) + ".");
            } else {
                this.setDnsServers(ResolverConfig.getCurrentConfig().servers().stream().map(InetSocketAddress::toString).collect(Collectors.joining(",")));
                this.setResolver(new ExtendedResolver());
                if (log.isInfoEnabled()) log.info("Created default DNS resolver.");
            }
        } catch (UnknownHostException ex) {
            throw new ResolutionException("Unable to create DNS resolver: " + ex.getMessage(), ex);
        }
    }

    public String lookup(String fqdn) throws ResolutionException {

        Lookup lookup = null;
        List<Record> records;

        try {

            lookup = new Lookup(fqdn, Type.URI);
            lookup.setResolver(this.getResolver());
            Record[] lookupResult = lookup.run();
            if (lookupResult == null || lookupResult.length < 1) return null;
            records = new ArrayList<>(Arrays.asList(lookupResult));
        } catch (Exception ex) {

            throw new ResolutionException("DNS resolution problem: " + ex.getMessage() + (lookup != null ? (" (" + lookup.getErrorString() + ")") : ""));
        }

        if (lookup.getErrorString() != null && ! "successful".equals(lookup.getErrorString())) {

            if (log.isDebugEnabled()) log.debug("For FQDN " + fqdn + " got error: " + lookup.getErrorString());
            throw new ResolutionException("DNS resolution error: " + lookup.getErrorString());
        }

        for (Record record : records) {
            URIRecord uriRecord = (URIRecord) record;
            if (log.isDebugEnabled()) log.debug("For FQDN " + fqdn + " found entry " + uriRecord.getTarget() + " with preference " + uriRecord.getPriority());
        }

        records.sort(Comparator.comparingInt(record -> ((URIRecord) record).getPriority()));
        if (log.isDebugEnabled()) log.debug("Sorted records according to priority: " + records);

        return ((URIRecord) records.get(0)).getTarget();
    }

    /*
     * Getters and setters
     */

    public String getDnsServers() {
        return dnsServers;
    }

    public void setDnsServers(String dnsServers) {
        this.dnsServers = dnsServers;
    }

    public Resolver getResolver() {
        return resolver;
    }

    public void setResolver(Resolver resolver) {
        this.resolver = resolver;
    }
}
