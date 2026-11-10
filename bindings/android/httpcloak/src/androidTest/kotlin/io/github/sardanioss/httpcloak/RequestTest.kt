package io.github.sardanioss.httpcloak

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RequestTest {
    private val session = Session(SessionConfig(preset = Presets.CHROME_LATEST))

    @After
    fun tearDown() = session.close()

    private fun Response.jsonObject() = json() as JSONObject

    @Test
    fun suspendingGet() = runBlocking {
        val response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
        assertEquals(200, response.statusCode)
        assertTrue(response.ok)
        assertTrue(response.text, response.text.contains("h=www.cloudflare.com"))
        assertTrue(response.protocol in listOf("h2", "h3"))
        assertTrue(response.elapsedMillis > 0)
    }

    @Test
    fun blockingGet() {
        val response = session.execute(Request("https://www.cloudflare.com/cdn-cgi/trace"))
        assertEquals(200, response.statusCode)
        assertTrue(response.text.contains("h=www.cloudflare.com"))
    }

    @Test
    fun fingerprintLooksLikeChrome() = runBlocking {
        val info = session.get("https://tls.peet.ws/api/all").jsonObject()
        assertTrue(info.getString("user_agent").contains("Chrome/"))
        assertTrue(info.getJSONObject("tls").getString("ja4").startsWith("t13d"))
        assertEquals("h2", info.getString("http_version"))
    }

    @Test
    fun http3() = runBlocking {
        Session(SessionConfig(httpVersion = "h3")).use { h3 ->
            val response = h3.get("https://www.cloudflare.com/cdn-cgi/trace")
            assertEquals("h3", response.protocol)
            assertTrue(response.text.contains("http=http/3"))
        }
    }

    @Test
    fun paramsHeadersCookiesAndAuth() = runBlocking {
        session.auth = "user" to "secret"
        val request = Request(
            url = "https://httpbin.org/get?fixed=1",
            headers = mapOf("X-Custom" to "yes"),
            params = mapOf("q" to "a b&c", "emoji" to "👋"),
            cookies = mapOf("flavour" to "oat"),
        )
        for (response in listOf(session.request(request), session.execute(request))) {
            val echo = response.jsonObject()
            val args = echo.getJSONObject("args")
            assertEquals("1", args.getString("fixed"))
            assertEquals("a b&c", args.getString("q"))
            assertEquals("👋", args.getString("emoji"))
            val headers = echo.getJSONObject("headers")
            assertEquals("yes", headers.getString("X-Custom"))
            assertEquals("flavour=oat", headers.getString("Cookie"))
            assertEquals("Basic dXNlcjpzZWNyZXQ=", headers.getString("Authorization"))
        }
    }

    @Test
    fun textAndBinaryBodiesRoundTripOnBothPaths() = runBlocking {
        val text = "héllo 👋 \u0000 world"
        val binary = ByteArray(4096) { it.toByte() }
        for (send in listOf<suspend (Request) -> Response>({ session.request(it) }, { session.execute(it) })) {
            val echoedText = send(Request("https://httpbin.org/post", "POST", body = Body.text(text, "text/plain")))
            // httpbin echoes a body holding a NUL as a data URI, however it is typed.
            val textData = echoedText.jsonObject().getString("data")
            val echoed = if (textData.startsWith("data:")) String(base64Decode(textData.substringAfter(",")), Charsets.UTF_8) else textData
            assertEquals(text, echoed)

            val json = send(Request("https://httpbin.org/post", "POST", body = Body.text("""{"a":"ü"}""")))
            assertEquals("ü", json.jsonObject().getJSONObject("json").getString("a"))

            val echoedBinary = send(Request("https://httpbin.org/anything", "PUT", body = Body(binary)))
            val data = echoedBinary.jsonObject().getString("data")
            assertTrue(data.startsWith("data:application/octet-stream;base64,"))
            assertArrayEquals(binary, base64Decode(data.substringAfter(",")))
        }
    }

    @Test
    fun binaryResponseBodyOnBothPaths() = runBlocking {
        val request = Request("https://httpbin.org/bytes/65536?seed=7")
        val viaAsync = session.request(request).body
        val viaBlocking = session.execute(request).body
        assertEquals(65536, viaAsync.size)
        assertArrayEquals(viaAsync, viaBlocking)
    }

    @Test
    fun formAndMultipart() = runBlocking {
        val form = session.post("https://httpbin.org/post", Body.form(mapOf("a" to "1 2", "b" to "ç")))
        assertEquals("1 2", form.jsonObject().getJSONObject("form").getString("a"))
        assertEquals("ç", form.jsonObject().getJSONObject("form").getString("b"))

        val multipart = session.post(
            "https://httpbin.org/post",
            Body.multipart(
                fields = mapOf("field" to "value"),
                files = mapOf("upload" to MultipartFile("file content".toByteArray(), "a.txt", "text/plain")),
            ),
        ).jsonObject()
        assertEquals("value", multipart.getJSONObject("form").getString("field"))
        assertEquals("file content", multipart.getJSONObject("files").getString("upload"))
        assertTrue(multipart.getJSONObject("headers").getString("Content-Type").contains("WebKitFormBoundary"))
    }

    @Test
    fun everyMethod() = runBlocking {
        assertEquals(200, session.put("https://httpbin.org/put", Body.json("{}")).statusCode)
        assertEquals(200, session.patch("https://httpbin.org/patch", Body.json("{}")).statusCode)
        assertEquals(200, session.delete("https://httpbin.org/delete").statusCode)
        val head = session.head("https://httpbin.org/get")
        assertEquals(200, head.statusCode)
        assertEquals(0, head.body.size)
        assertTrue(session.options("https://httpbin.org/get").statusCode < 500)
    }

    @Test
    fun redirects() = runBlocking {
        val followed = session.get("https://httpbin.org/redirect/2")
        assertEquals(200, followed.statusCode)
        assertEquals(2, followed.history.size)
        assertEquals("https://httpbin.org/get", followed.url)

        val notFollowed = session.request(Request("https://httpbin.org/redirect/1", allowRedirects = false))
        assertEquals(302, notFollowed.statusCode)
        assertTrue(notFollowed.header("location")!!.isNotEmpty())
    }

    @Test
    fun exactHeadersGoOutAsGiven() = runBlocking {
        val echo = session.request(
            Request(
                "https://httpbin.org/headers",
                exactHeaders = listOf("X-First" to "1", "User-Agent" to "exact"),
            ),
        ).jsonObject().getJSONObject("headers")
        assertEquals("exact", echo.getString("User-Agent"))
        assertEquals("1", echo.getString("X-First"))
    }

    @Test
    fun errorStatusAndRaiseForStatus() = runBlocking {
        val response = session.get("https://httpbin.org/status/418")
        assertEquals(418, response.statusCode)
        try {
            response.raiseForStatus()
            fail("expected HttpCloakException")
        } catch (e: HttpCloakException) {
            assertEquals(response, e.response)
        }
    }

    @Test
    fun networkErrorsCarryTheReason() = runBlocking {
        val request = Request("https://nonexistent.invalid/")
        for (send in listOf<suspend () -> Response>({ session.request(request) }, { session.execute(request) })) {
            try {
                send()
                fail("expected HttpCloakException")
            } catch (e: HttpCloakException) {
                assertTrue(e.message!!, e.message!!.isNotBlank() && e.message != "request failed")
            }
        }
    }

    @Test
    fun cancellingTheCoroutineAbortsTheRequest() = runBlocking {
        val start = System.nanoTime()
        try {
            withTimeout(1000) { session.get("https://httpbin.org/delay/10") }
            fail("expected a timeout")
        } catch (_: TimeoutCancellationException) {
        }
        assertTrue((System.nanoTime() - start) / 1_000_000 < 3000)
        // The session is still usable afterwards.
        assertEquals(200, session.get("https://httpbin.org/get").statusCode)
    }

    @Test
    fun perRequestTimeout() = runBlocking {
        val request = Request("https://httpbin.org/delay/5", timeout = 1)
        for (send in listOf<suspend () -> Response>({ session.request(request) }, { session.execute(request) })) {
            val start = System.nanoTime()
            try {
                send()
                fail("expected a timeout")
            } catch (_: HttpCloakException) {
            }
            assertTrue((System.nanoTime() - start) / 1_000_000 < 4000)
        }
    }

    @Test
    fun concurrentRequests() = runBlocking {
        val statuses = (1..10).map { async { session.get("https://httpbin.org/get?i=$it").statusCode } }.awaitAll()
        assertEquals(List(10) { 200 }, statuses)
    }
}
