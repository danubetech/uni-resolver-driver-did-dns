package uniresolver.driver.did.dns;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.did.jsonld.DIDKeywords;
import foundation.identity.jsonld.JsonLDKeywords;
import foundation.identity.jsonld.JsonLDUtils;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.driver.Driver;
import uniresolver.result.ResolveDataModelResult;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DidDnsDriver implements Driver {

	public static final Pattern DID_DNS_PATTERN = Pattern.compile("^did:dns:(.+)$");

	private Map<String, Object> properties;

	private String dnsServers;
	private String didKeyResolver;

	private DnsResolver dnsResolver = null;
	private ClientUniResolver clientUniResolver = null;

	public DidDnsDriver(Map<String, Object> properties) {
		this.setProperties(properties);
	}

	public DidDnsDriver() {
		this(getPropertiesFromEnvironment());
	}

	private static Map<String, Object> getPropertiesFromEnvironment() {

		if (log.isDebugEnabled()) log.debug("Loading from environment: " + System.getenv());

		Map<String, Object> properties = new HashMap<String, Object> ();

		try {

			String env_dnsServers = System.getenv("uniresolver_driver_did_dns_dnsServers");
			String env_didKeyResolver = System.getenv("uniresolver_driver_did_dns_didKeyResolver");

			if (env_dnsServers != null) properties.put("dnsServers", env_dnsServers);
			if (env_didKeyResolver != null) properties.put("didKeyResolver", env_didKeyResolver);
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}

		return properties;
	}

	private void configureFromProperties() {

		if (log.isDebugEnabled()) log.debug("Configuring from properties: " + this.getProperties());

		try {

			String env_dnsServers = (String) this.getProperties().get("dnsServers");
			String env_didKeyResolver = (String) this.getProperties().get("didKeyResolver");

			if (env_dnsServers != null) this.setDnsServers(env_dnsServers);
			if (env_didKeyResolver != null) this.setDidKeyResolver(env_didKeyResolver);
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	@Override
	public ResolveDataModelResult resolve(DID did, Map<String, Object> resolveOptions) throws ResolutionException {

		// open resolvers

		synchronized (this) {
			if (this.getDnsResolver() == null) this.openDnsResolver();
		}

		synchronized (this) {
			if (this.getClientUniResolver() == null) this.openClientUniResolver();;
		}

		// parse identifier

		Matcher matcher = DID_DNS_PATTERN.matcher(did.getDidString());
		if (! matcher.matches()) return null;

		String domainName = matcher.group(1);

		// DNS lookup

		Set<URI> contexts = new HashSet<>(Arrays.asList(DIDDocument.DEFAULT_JSONLD_CONTEXTS));
		List<Object> allVerificationMethods = new ArrayList<>();
		List<Object> allAuthenticationVerificationMethods = new ArrayList<>();
		List<Object> allAssertionMethodVerificationMethods = new ArrayList<>();
		List<Object> allCapabilityInvocationVerificationMethods = new ArrayList<>();
		List<Object> allCapabilityDelegationVerificationMethods = new ArrayList<>();
		List<Object> allKeyAgreementVerificationMethods = new ArrayList<>();

		for (int i=1; ; i++) {

			// resolve DNS

			DnsResolver dnsResolver = new DnsResolver(this.getDnsServers());

			String keyId = "key" + i;
			String fqdn = "_" + keyId + "._did." + domainName;
			String target = this.getDnsResolver().lookup(fqdn);

			if (target == null) {
				if (log.isDebugEnabled()) log.warn("For FQDN " + fqdn + " found nothing. Assuming all verification methods have been found.");
				break;
			}

			if (! target.startsWith("did:key:")) {
				if (log.isWarnEnabled()) log.warn("For FQDN " + fqdn + " found something other than did:key: " + target);
				continue;
			}

			// resolve did:key

			DIDDocument didKeyDidDocument = this.getClientUniResolver().resolve(target).getDidDocument();
			if (log.isDebugEnabled()) log.debug("Resolved " + target + " to " + didKeyDidDocument);

			contexts.addAll(didKeyDidDocument.getContexts());
			if (log.isDebugEnabled()) log.debug("Contexts now: " + contexts);

			List<Object> verificationMethods = JsonLDUtils.jsonLdGetJsonArray(didKeyDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
			List<Object> authenticationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(didKeyDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_AUTHENTICATION);
			List<Object> assertionMethodVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(didKeyDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD);
			List<Object> capabilityInvocationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(didKeyDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION);
			List<Object> capabilityDelegationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(didKeyDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION);
			List<Object> keyAgreementVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(didKeyDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_KEYAGREEMENT);

			if (verificationMethods != null) allVerificationMethods.addAll(rewriteIdAndController(verificationMethods, target, did.toString(), keyId));
			if (authenticationVerificationMethods != null) allAuthenticationVerificationMethods.addAll(rewriteIdAndController(authenticationVerificationMethods, target, did.toString(), keyId));
			if (assertionMethodVerificationMethods != null) allAssertionMethodVerificationMethods.addAll(rewriteIdAndController(assertionMethodVerificationMethods, target, did.toString(), keyId));
			if (capabilityInvocationVerificationMethods != null) allCapabilityInvocationVerificationMethods.addAll(rewriteIdAndController(capabilityInvocationVerificationMethods, target, did.toString(), keyId));
			if (capabilityDelegationVerificationMethods != null) allCapabilityDelegationVerificationMethods.addAll(rewriteIdAndController(capabilityDelegationVerificationMethods, target, did.toString(), keyId));
			if (keyAgreementVerificationMethods != null) allKeyAgreementVerificationMethods.addAll(rewriteIdAndController(keyAgreementVerificationMethods, target, did.toString(), keyId));
			if (log.isDebugEnabled()) log.debug("All verification methods now: " + allVerificationMethods);
		}

		if (allVerificationMethods.isEmpty()) return null;

		// create DID DOCUMENT

		DIDDocument didDocument = DIDDocument.builder()
				.defaultContexts(false)
				.contexts(new ArrayList<>(contexts))
				.id(did.toUri())
				.build();

		JsonLDUtils.jsonLdAddAsJsonArray(didDocument, DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD, allVerificationMethods);
		JsonLDUtils.jsonLdAddAsJsonArray(didDocument, DIDKeywords.JSONLD_TERM_AUTHENTICATION, allAuthenticationVerificationMethods);
		JsonLDUtils.jsonLdAddAsJsonArray(didDocument, DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD, allAssertionMethodVerificationMethods);
		JsonLDUtils.jsonLdAddAsJsonArray(didDocument, DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION, allCapabilityInvocationVerificationMethods);
		JsonLDUtils.jsonLdAddAsJsonArray(didDocument, DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION, allCapabilityDelegationVerificationMethods);
		JsonLDUtils.jsonLdAddAsJsonArray(didDocument, DIDKeywords.JSONLD_TERM_KEYAGREEMENT, allKeyAgreementVerificationMethods);

		// create DID DOCUMENT METADATA

		Map<String, Object> didDocumentMetadata = new LinkedHashMap<> ();
		didDocumentMetadata.put("dnsServers", this.getDnsResolver().getDnsServers());
		didDocumentMetadata.put("didKeyResolver", this.getDidKeyResolver());

		// create RESOLVE RESULT

		ResolveDataModelResult resolveDataModelResult = ResolveDataModelResult.build(null, didDocument, didDocumentMetadata);

		// done

		return resolveDataModelResult;
	}

	@Override
	public Map<String, Object> properties() {
		return this.getProperties();
	}

	private void openDnsResolver() throws ResolutionException {

		// init DNS resolver

		DnsResolver dnsResolver = new DnsResolver(this.getDnsServers());
		dnsResolver.init();
		this.setDnsResolver(dnsResolver);
	}

	private void openClientUniResolver() {

		// init did:key resolver

		ClientUniResolver clientUniResolver = ClientUniResolver.create(URI.create(this.getDidKeyResolver()));
		this.setClientUniResolver(clientUniResolver);
		if (log.isInfoEnabled()) log.info("Created did:key resolver: " + this.getDidKeyResolver());
	}

	/*
	 * Helper methods
	 */

	private List<Object> rewriteIdAndController(List<Object> verificationMethods, String didKeyDid, String didDnsDid, String dnsKeyId) {
		if (log.isDebugEnabled()) log.debug("Verification methods before rewrite: " + verificationMethods);
		List<Object> rewrittenVerificationMethods = new ArrayList<>();

		for (Iterator<Object> i = verificationMethods.listIterator(); i.hasNext(); ) {
			Object verificationMethod = i.next();
			if (verificationMethod instanceof String) {
				String verificationMethodId = (String) verificationMethod;
				if (! verificationMethodId.startsWith(didKeyDid + "#")) {
					log.warn("Skipping unexpected verification method ID, since it doesn't start with \"" + (didKeyDid + "#") + "\": " + verificationMethodId);
					continue;
				}
				String rewrittenVerificationMethodId = rewriteVerificationMethodId(verificationMethodId, didKeyDid, didDnsDid);

				rewrittenVerificationMethods.add(rewrittenVerificationMethodId);
			} else if (verificationMethod instanceof Map) {
				VerificationMethod verificationMethodJsonLd = VerificationMethod.fromJsonObject((Map<String, Object>) verificationMethod);

				String verificationMethodId = verificationMethodJsonLd.getId().toString();
				if (! verificationMethodId.startsWith(didKeyDid + "#")) {
					log.warn("Skipping unexpected verification method ID, since it doesn't start with \"" + (didKeyDid + "#") + "\": " + verificationMethodId);
					continue;
				}
				String rewrittenVerificationMethodId = rewriteVerificationMethodId(verificationMethodId, didKeyDid, didDnsDid);
				JsonLDUtils.jsonLdRemove(verificationMethodJsonLd, JsonLDKeywords.JSONLD_TERM_ID);
				JsonLDUtils.jsonLdAdd(verificationMethodJsonLd, JsonLDKeywords.JSONLD_TERM_ID, rewrittenVerificationMethodId);

				String verificationMethodController = verificationMethodJsonLd.getController();
				if (! verificationMethodController.equals(didKeyDid)) {
					log.warn("Skipping unexpected verification method controller, since it is not \"" + didKeyDid + "\": " + verificationMethodController);
					continue;
				}
				String rewrittenVerificationMethodController = didDnsDid;
				JsonLDUtils.jsonLdRemove(verificationMethodJsonLd, DIDKeywords.JSONLD_TERM_CONTROLLER);
				JsonLDUtils.jsonLdAdd(verificationMethodJsonLd, DIDKeywords.JSONLD_TERM_CONTROLLER, rewrittenVerificationMethodController);

				rewrittenVerificationMethods.add(verificationMethod);
			} else {
				log.warn("Skipping unexpected verification method: " + verificationMethod);
			}
		}

		if (log.isDebugEnabled()) log.debug("Verification methods after rewrite: " + rewrittenVerificationMethods);
		return rewrittenVerificationMethods;
	}

	private String rewriteVerificationMethodId(String id, String didKeyDid, String didDnsDid) {
		String rewrittenId = id;
		rewrittenId = rewrittenId.replace(didKeyDid, didDnsDid);
		return rewrittenId;
	}

	/*
	 * Getters and setters
	 */

	public Map<String, Object> getProperties() {
		return this.properties;
	}

	public void setProperties(Map<String, Object> properties) {
		this.properties = properties;
		this.configureFromProperties();
	}

	public String getDnsServers() {
		return this.dnsServers;
	}

	public void setDnsServers(String dnsServers) {
		this.dnsServers = dnsServers;
	}

	public String getDidKeyResolver() {
		return this.didKeyResolver;
	}

	public void setDidKeyResolver(String didKeyResolver) {
		this.didKeyResolver = didKeyResolver;
	}

	public DnsResolver getDnsResolver() {
		return this.dnsResolver;
	}

	public void setDnsResolver(DnsResolver dnsResolver) {
		this.dnsResolver = dnsResolver;
	}

	public ClientUniResolver getClientUniResolver() {
		return this.clientUniResolver;
	}

	public void setClientUniResolver(ClientUniResolver clientUniResolver) {
		this.clientUniResolver = clientUniResolver;
	}
}
