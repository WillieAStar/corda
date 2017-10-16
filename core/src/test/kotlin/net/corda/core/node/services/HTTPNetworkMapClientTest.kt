package net.corda.core.node.services

import com.fasterxml.jackson.databind.ObjectMapper
import net.corda.core.crypto.*
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.node.NodeInfo
import net.corda.core.serialization.SerializationDefaults
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.node.serialization.KryoServerSerializationScheme
import net.corda.node.utilities.CertificateType
import net.corda.node.utilities.X509Utilities
import net.corda.nodeapi.internal.serialization.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.handler.HandlerCollection
import org.eclipse.jetty.servlet.ServletContextHandler
import org.eclipse.jetty.servlet.ServletHolder
import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.servlet.ServletContainer
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.security.cert.CertPath
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.ws.rs.*
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response
import javax.ws.rs.core.Response.ok
import kotlin.test.assertEquals

internal class HTTPNetworkMapClientTest {
    private lateinit var server: Server

    private lateinit var networkMapClient: NetworkMapClient
    private val rootCAKey = Crypto.generateKeyPair(X509Utilities.DEFAULT_TLS_SIGNATURE_SCHEME)
    private val rootCACert = X509Utilities.createSelfSignedCACertificate(CordaX500Name(commonName = "Corda Node Root CA", organisation = "R3 LTD", locality = "London", country = "GB"), rootCAKey)
    private val intermediateCAKey = Crypto.generateKeyPair(X509Utilities.DEFAULT_TLS_SIGNATURE_SCHEME)
    private val intermediateCACert = X509Utilities.createCertificate(CertificateType.INTERMEDIATE_CA, rootCACert, rootCAKey, X500Name("CN=Corda Node Intermediate CA,L=London"), intermediateCAKey.public)

    companion object {
        @BeforeClass
        @JvmStatic
        fun initSerialization() {
            try {
                SerializationDefaults.SERIALIZATION_FACTORY = SerializationFactoryImpl().apply {
                    registerScheme(KryoServerSerializationScheme())
                    registerScheme(AMQPServerSerializationScheme())
                }
                SerializationDefaults.P2P_CONTEXT = KRYO_P2P_CONTEXT
                SerializationDefaults.RPC_SERVER_CONTEXT = KRYO_RPC_SERVER_CONTEXT
                SerializationDefaults.STORAGE_CONTEXT = KRYO_STORAGE_CONTEXT
                SerializationDefaults.CHECKPOINT_CONTEXT = KRYO_CHECKPOINT_CONTEXT
            } catch (ignored: Exception) {
                // Ignored
            }
        }
    }

    @Before
    fun setUp() {
        server = Server(InetSocketAddress("localhost", 0)).apply {
            handler = HandlerCollection().apply {
                addHandler(ServletContextHandler().apply {
                    contextPath = "/"
                    val resourceConfig = ResourceConfig().apply {
                        // Add your API provider classes (annotated for JAX-RS) here
                        register(MockNetworkMapServer())
                    }
                    val jerseyServlet = ServletHolder(ServletContainer(resourceConfig)).apply { initOrder = 0 }// Initialise at server start
                    addServlet(jerseyServlet, "/api/*")
                })
            }
        }
        server.start()

        while (!server.isStarted) {
            Thread.sleep(100)
        }

        val hostAndPort = server.connectors.mapNotNull { it as? ServerConnector }
                .first()
        networkMapClient = HTTPNetworkMapClient("http://${hostAndPort.host}:${hostAndPort.localPort}/api/network-map")
    }

    @After
    fun tearDown() {
        server.stop()
    }

    @Test
    fun register() {
        // Create node info.
        val signedNodeInfo = createStubedNodeInfo("Test1")
        val nodeInfo = signedNodeInfo.verified()

        networkMapClient.register(signedNodeInfo)

        val nodeInfoHash = nodeInfo.serialize().sha256()

        assertEquals(listOf(nodeInfoHash), networkMapClient.getNetworkMap())
        assertEquals(nodeInfo, networkMapClient.getNodeInfo(nodeInfoHash))

        val signedNodeInfo2 = createStubedNodeInfo("Test2")
        val nodeInfo2 = signedNodeInfo2.verified()
        networkMapClient.register(signedNodeInfo2)

        val nodeInfoHash2 = nodeInfo2.serialize().sha256()
        assertEquals(listOf(nodeInfoHash, nodeInfoHash2).sorted(), networkMapClient.getNetworkMap().sorted())
        assertEquals(nodeInfo2, networkMapClient.getNodeInfo(nodeInfoHash2))
    }

    private fun createStubedNodeInfo(name: String): SignedData<NodeInfo> {
        val keyPair = Crypto.generateKeyPair(X509Utilities.DEFAULT_TLS_SIGNATURE_SCHEME)
        val clientCert = X509Utilities.createCertificate(CertificateType.CLIENT_CA, intermediateCACert, intermediateCAKey, CordaX500Name(organisation = name, locality = "London", country = "GB"), keyPair.public)
        val certPath = buildCertPath(clientCert.toX509Certificate(), intermediateCACert.toX509Certificate(), rootCACert.toX509Certificate())
        val nodeInfo = NodeInfo(listOf(NetworkHostAndPort("my.$name.com", 1234)), listOf(PartyAndCertificate(certPath)), 1, serial = 1L)

        // Create digital signature.
        val digitalSignature = DigitalSignature.WithKey(keyPair.public, Crypto.doSign(keyPair.private, nodeInfo.serialize().bytes))

        return SignedData(nodeInfo.serialize(), digitalSignature)
    }
}

@Path("network-map")
internal class MockNetworkMapServer {
    private val nodeInfos = mutableMapOf<SecureHash, NodeInfo>()
    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    fun registerNode(input: InputStream): Response {
        val registrationData = input.readBytes().deserialize<SignedData<NodeInfo>>()
        val nodeInfo = registrationData.verified()
        val nodeInfoHash = nodeInfo.serialize().sha256()
        nodeInfos.put(nodeInfoHash, nodeInfo)
        return ok().build()
    }

    @GET
    @Path("")
    @Produces(MediaType.APPLICATION_JSON)
    fun getNetworkMap(): Response {
        return Response.ok(ObjectMapper().writeValueAsString(nodeInfos.keys.map { it.toString() })).build()
    }

    @GET
    @Path("{var}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    fun getNodeInfo(@PathParam("var") nodeInfoHash: String): Response {
        return nodeInfos[SecureHash.parse(nodeInfoHash)]?.let {
            Response.ok(it.serialize().bytes).build()
        } ?: Response.status(Response.Status.NOT_FOUND).build()
    }
}

private fun buildCertPath(vararg certificates: Certificate): CertPath {
    return CertificateFactory.getInstance("X509").generateCertPath(certificates.asList())
}

private fun X509CertificateHolder.toX509Certificate(): X509Certificate {
    return CertificateFactory.getInstance("X509").generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
}