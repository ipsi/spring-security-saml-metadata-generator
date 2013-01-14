package nz.net.ipsi.spring.saml.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.opensaml.PaosBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.w3c.dom.Element;

import com.beust.jcommander.IVariableArity;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

public class GenerateMetadata {

	public static enum AllowedSSOBindings {
		SSO_POST, SSO_PAOS, SSO_ARTIFACT, HOKSSO_POST, HOKSSO_ARTIFACT
	}

	/**
	 * @param args
	 * @throws IOException
	 * @throws MarshallingException
	 */
	public static void main(final String[] args) throws Exception {
		final Arguments arguments = new Arguments();
		final JCommander commander = new JCommander(arguments);
		try {
			commander.parse(args);
		}
		catch (final ParameterException e) {
			System.err.println(e.getMessage());
			final StringBuilder builder = new StringBuilder();
			commander.usage(builder);
			System.err.println(builder);
			return;
		}

		final KeyStore keystore = KeyStore.getInstance("jks");
		InputStream keystoreStream = null;
		try {
			keystoreStream = new FileInputStream(arguments.getKeystore());
			keystore.load(keystoreStream, arguments.getKeystorePassword().toCharArray());
		}
		finally {
			if (keystoreStream != null)
				keystoreStream.close();
		}

		final Map<String, String> keyPasswords = new HashMap<>();

		if (arguments.getEncryptionKey() != null)
			keyPasswords.put(arguments.getEncryptionKey(), arguments.getEncryptionKeyPassword());

		if (arguments.getSigningKey() != null)
			keyPasswords.put(arguments.getSigningKey(), arguments.getSigningKeyPassword());

		if (arguments.getTlsKey() != null)
			keyPasswords.put(arguments.getTlsKey(), arguments.getTlsKeyPassword());

		bootstrap();

		final JKSKeyManager keyManager = new JKSKeyManager(keystore, keyPasswords, null);
		final MetadataGenerator generator = new MetadataGenerator();
		generator.setKeyManager(keyManager);

		generator.setEntityId(arguments.getEntityId());
		generator.setEntityAlias(arguments.getAlias());
		generator.setEntityBaseURL(arguments.getBaseURL());
		generator.setSignMetadata(arguments.isSignMetadata());
		generator.setRequestSigned(arguments.isRequestSigned());
		generator.setWantAssertionSigned(arguments.isWantAssertionSigned());
		generator.setSigningKey(arguments.getSigningKey());
		generator.setEncryptionKey(arguments.getEncryptionKey());

		if (arguments.getTlsKey() != null && arguments.getTlsKey().length() > 0) {
			generator.setTlsKey(arguments.getTlsKey());
		}

		final Collection<String> bindingsSSO = new LinkedList<String>();
		final Collection<String> bindingsHoKSSO = new LinkedList<String>();
		final AllowedSSOBindings defaultBinding = arguments.getSsoDefaultBinding();

		int assertionConsumerIndex = 0;

		for (final AllowedSSOBindings binding : arguments.getSsoBindings()) {

			// Set default binding
			if (binding.equals(defaultBinding)) {
				assertionConsumerIndex = bindingsSSO.size() + bindingsHoKSSO.size();
			}

			// Set included bindings
			if (AllowedSSOBindings.SSO_POST.equals(binding)) {
				bindingsSSO.add(SAMLConstants.SAML2_POST_BINDING_URI);
			}
			else if (AllowedSSOBindings.SSO_ARTIFACT.equals(binding)) {
				bindingsSSO.add(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
			}
			else if (AllowedSSOBindings.SSO_PAOS.equals(binding)) {
				bindingsSSO.add(SAMLConstants.SAML2_PAOS_BINDING_URI);
			}
			else if (AllowedSSOBindings.HOKSSO_POST.equals(binding)) {
				bindingsHoKSSO.add(SAMLConstants.SAML2_POST_BINDING_URI);
			}
			else if (AllowedSSOBindings.HOKSSO_ARTIFACT.equals(binding)) {
				bindingsHoKSSO.add(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
			}

		}

		// Set bindings
		generator.setBindingsSSO(bindingsSSO);
		generator.setBindingsHoKSSO(bindingsHoKSSO);
		generator.setAssertionConsumerIndex(assertionConsumerIndex);

		// Discovery
		if (arguments.isIncludeDiscovery()) {
			generator.setIncludeDiscovery(true);
			if (arguments.getCustomDiscoveryURL() != null && arguments.getCustomDiscoveryURL().length() > 0) {
				generator.setCustomDiscoveryURL(arguments.getCustomDiscoveryURL());
			}
		}
		else {
			generator.setIncludeDiscovery(false);
		}

		generator.setNameID(arguments.getNameID());

		final EntityDescriptor descriptor = generator.generateMetadata();
		final ExtendedMetadata extendedMetadata = generator.generateExtendedMetadata();
		extendedMetadata.setSecurityProfile(arguments.getSecurityProfile());
		extendedMetadata.setSslSecurityProfile(arguments.getSslSecurityProfile());
		extendedMetadata.setRequireLogoutRequestSigned(arguments.isRequireLogoutRequestSigned());
		extendedMetadata.setRequireLogoutResponseSigned(arguments.isRequireLogoutResponseSigned());
		extendedMetadata.setRequireArtifactResolveSigned(arguments.isRequireArtifactResolveSigned());

		Writer metadataWriter = null;
		try {
			metadataWriter = new FileWriter(arguments.getMetadataOutput());
			metadataWriter.write(getMetadataAsString(descriptor));
		}
		finally {
			if (metadataWriter != null) {
				metadataWriter.flush();
				metadataWriter.close();
			}
		}

		if (arguments.getExtendedMetadataOutput() != null) {
			Writer extendedMetadataWriter = null;
			try {
				extendedMetadataWriter = new FileWriter(arguments.getExtendedMetadataOutput());
				extendedMetadataWriter.write(getConfiguration(arguments.getExtendedMetadataOutput().getName(), extendedMetadata));
			}
			finally {
				if (extendedMetadataWriter != null) {
					extendedMetadataWriter.flush();
					extendedMetadataWriter.close();
				}
			}
		}
	}

	private static void bootstrap() throws ConfigurationException {
		PaosBootstrap.bootstrap();

		NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
		X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
		generator.setEmitEntityCertificate(true);
		generator.setEmitEntityCertificateChain(true);
		manager.registerFactory(org.springframework.security.saml.SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR, generator);
	}

	private static String getMetadataAsString(final EntityDescriptor descriptor) throws MarshallingException {

		final MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		final Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);
		final Element element = marshaller.marshall(descriptor);
		return XMLHelper.nodeToString(element);

	}

	private static String getConfiguration(final String fileName, final ExtendedMetadata extendedMetadata) {
		final StringBuilder sb = new StringBuilder();
		sb.append("<bean class=\"org.springframework.security.saml.metadata.ExtendedMetadataDelegate\">\n");
		sb.append("    <constructor-arg>\n");
		sb.append("        <bean class=\"org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider\">\n");
		sb.append("            <constructor-arg>\n");
		sb.append("                <value type=\"java.io.File\">classpath:security/").append(fileName).append("</value>\n");
		sb.append("            </constructor-arg>\n");
		sb.append("            <property name=\"parserPool\" ref=\"parserPool\"/>\n");
		sb.append("        </bean>\n");
		sb.append("    </constructor-arg>\n");
		sb.append("    <constructor-arg>\n");
		sb.append("        <bean class=\"org.springframework.security.saml.metadata.ExtendedMetadata\">\n");
		sb.append("           <property name=\"local\" value=\"true\"/>\n");
		sb.append("           <property name=\"alias\" value=\"").append(extendedMetadata.getAlias()).append("\"/>\n");
		sb.append("           <property name=\"securityProfile\" value=\"").append(extendedMetadata.getSecurityProfile()).append("\"/>\n");
		sb.append("           <property name=\"sslSecurityProfile\" value=\"").append(extendedMetadata.getSslSecurityProfile()).append("\"/>\n");
		sb.append("           <property name=\"signingKey\" value=\"").append(extendedMetadata.getSigningKey()).append("\"/>\n");
		sb.append("           <property name=\"encryptionKey\" value=\"").append(extendedMetadata.getEncryptionKey()).append("\"/>\n");

		if (extendedMetadata.getTlsKey() != null) {
			sb.append("           <property name=\"tlsKey\" value=\"").append(extendedMetadata.getTlsKey()).append("\"/>\n");
		}

		sb.append("           <property name=\"requireArtifactResolveSigned\" value=\"").append(extendedMetadata.isRequireArtifactResolveSigned()).append("\"/>\n");
		sb.append("           <property name=\"requireLogoutRequestSigned\" value=\"").append(extendedMetadata.isRequireLogoutRequestSigned()).append("\"/>\n");
		sb.append("           <property name=\"requireLogoutResponseSigned\" value=\"").append(extendedMetadata.isRequireLogoutResponseSigned()).append("\"/>\n");

		if (extendedMetadata.isIdpDiscoveryEnabled()) {
			sb.append("           <property name=\"idpDiscoveryURL\" value=\"").append(extendedMetadata.getIdpDiscoveryURL()).append("\"/>\n");
			sb.append("           <property name=\"idpDiscoveryResponseURL\" value=\"").append(extendedMetadata.getIdpDiscoveryResponseURL()).append("\"/>\n");
		}

		sb.append("        </bean>\n");
		sb.append("    </constructor-arg>\n");
		sb.append("</bean>");

		return sb.toString();
	}

	public static class Arguments implements IVariableArity {
		@Parameter(names = { "--entity-id" }, description = "Entity ID is a unique identifier for an identity or service provider. Value is included in the generated metadata.", required = true)
		private String						entityId;
		@Parameter(names = { "--security-profile" }, description = "Security profile determines how is trust of digital signatures handled. Must be one of metaiop or pkix")
		private String						securityProfile		= "metaiop";
		@Parameter(names = { "--ssl-security-profile" }, description = "SSL/TLS Security profile determines how is trust of peer's SSL/TLS certificate (e.g. during Artifact resolution) handled. Must be one of metaiop or pkix")
		private String						sslSecurityProfile	= "pkix";
		@Parameter(names = { "--base-url" }, description = "Base to generate URLs for this server. For example: https://myServer:443/saml-app. The public address your server will be accessed from should be used here.", required = true)
		private String						baseURL;
		@Parameter(names = { "--alias" }, description = "Alias is an internal mechanism allowing collocating multiple service providers on one server. Alias must be unique.", required = true)
		private String						alias;
		@Parameter(names = { "--sign-metadata" }, description = "If the generated metadata will be digitally signed using the specified signature key.")
		private boolean						signMetadata;
		@Parameter(names = { "--name-id" }, description = "List of accepted NameID values (e.g. urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress)", variableArity = true)
		private List<String>				nameID;
		@Parameter(names = { "--sso-bindings" }, description = "Single sign-on bindings", variableArity = true)
		private List<AllowedSSOBindings>	ssoBindings			= Arrays.asList(new AllowedSSOBindings[] { AllowedSSOBindings.SSO_ARTIFACT, AllowedSSOBindings.SSO_POST });
		@Parameter(names = { "--sso-default-binding" }, description = "Which of the included SSO Bindings is the default.")
		private AllowedSSOBindings			ssoDefaultBinding	= AllowedSSOBindings.SSO_ARTIFACT;
		@Parameter(names = { "--signing-key" }, description = "Key used for digital signatures of SAML messages. Public key will be included in the metadata.")
		private String						signingKey;
		@Parameter(names = { "--signing-password" }, description = "Password to access the signing key.")
		private String						signingKeyPassword;
		@Parameter(names = { "--encryption-key" }, description = "Key used for digital encryption of SAML messages. Public key will be included in the metadata.")
		private String						encryptionKey;
		@Parameter(names = { "--encryption-password" }, description = "Password to access the encryption key.")
		private String						encryptionKeyPassword;
		@Parameter(names = { "--tls-client-key" }, description = "Key used to authenticate this instance for SSL/TLS connections.")
		private String						tlsKey;
		@Parameter(names = { "--tls-client-password" }, description = "Password to access the SSl/TLS client key.")
		private String						tlsKeyPassword;
		@Parameter(names = { "--include-discovery" }, description = "Enable IDP Discovery profile")
		private boolean						includeDiscovery;
		@Parameter(names = { "--custom-discovery-url" }, description = "When not set local IDP discovery URL is automatically generated when IDP discovery is enabled.")
		private String						customDiscoveryURL;
		@Parameter(names = { "--request-signed" }, description = "Sign sent AuthenticationRequests")
		private boolean						requestSigned;
		@Parameter(names = { "--want-assertion-signed" }, description = "Require signed authentication Assertion")
		private boolean						wantAssertionSigned;
		@Parameter(names = { "--require-logout-request-signed" }, description = "Require signed LogoutRequest")
		private boolean						requireLogoutRequestSigned;
		@Parameter(names = { "--require-logout-response-signed" }, description = "Require signed LogoutResponse")
		private boolean						requireLogoutResponseSigned;
		@Parameter(names = { "--require-artifact-resolve-signed" }, description = "Require signed ArtifactResolve")
		private boolean						requireArtifactResolveSigned;

		@Parameter(names = { "--metadata-output" }, description = "File to write SAML metadata out to", required = true)
		private File						metadataOutput;

		@Parameter(names = { "--extended-metadata-output" }, description = "File to write the extended metadata (Spring Bean XML) to")
		private File						extendedMetadataOutput;

		@Parameter(names = { "--keystore" }, description = "Keystore that contains the signing, encryption and tls keys", required = true)
		private File						keystore;

		@Parameter(names = { "--keystore-password" }, description = "password to access the keystore", required = true)
		private String						keystorePassword;

		public Arguments() {
			super();
		}

		public String getEntityId() {
			return entityId;
		}

		public String getSecurityProfile() {
			return securityProfile;
		}

		public String getSslSecurityProfile() {
			return sslSecurityProfile;
		}

		public String getBaseURL() {
			return baseURL;
		}

		public String getAlias() {
			return alias;
		}

		public boolean isSignMetadata() {
			return signMetadata;
		}

		public List<String> getNameID() {
			return nameID;
		}

		public List<AllowedSSOBindings> getSsoBindings() {
			return ssoBindings;
		}

		public AllowedSSOBindings getSsoDefaultBinding() {
			return ssoDefaultBinding;
		}

		public String getSigningKey() {
			return signingKey;
		}

		public String getEncryptionKey() {
			return encryptionKey;
		}

		public String getTlsKey() {
			return tlsKey;
		}

		public boolean isIncludeDiscovery() {
			return includeDiscovery;
		}

		public String getCustomDiscoveryURL() {
			return customDiscoveryURL;
		}

		public boolean isRequestSigned() {
			return requestSigned;
		}

		public boolean isWantAssertionSigned() {
			return wantAssertionSigned;
		}

		public boolean isRequireLogoutRequestSigned() {
			return requireLogoutRequestSigned;
		}

		public boolean isRequireLogoutResponseSigned() {
			return requireLogoutResponseSigned;
		}

		public boolean isRequireArtifactResolveSigned() {
			return requireArtifactResolveSigned;
		}

		public File getMetadataOutput() {
			return metadataOutput;
		}

		public File getExtendedMetadataOutput() {
			return extendedMetadataOutput;
		}

		public String getSigningKeyPassword() {
			return signingKeyPassword;
		}

		public String getEncryptionKeyPassword() {
			return encryptionKeyPassword;
		}

		public String getTlsKeyPassword() {
			return tlsKeyPassword;
		}

		public File getKeystore() {
			return keystore;
		}

		public String getKeystorePassword() {
			return keystorePassword;
		}

		@Override
		public int processVariableArity(String optionName, String[] options) {
			int count = 0;
			if (optionName.equals("--name-id") && options != null) {
				nameID = new ArrayList<>();
				for (String s : options) {
					if (s.startsWith("--"))
						return count;

					count++;
					nameID.add(s);
				}
			}
			else if (optionName.equals("--sso-bindings") && options != null) {
				ssoBindings = new ArrayList<>();
				for (String s : options) {
					if (s.startsWith("--"))
						return count;
					count++;
					ssoBindings.add(AllowedSSOBindings.valueOf(s));
				}
			}

			return options.length;
		}

	}
}
