package io.oakdom.xss.interceptor;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.annotation.OakdomXssExclude;
import io.oakdom.xss.annotation.OakdomXssFilterMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class OakdomXssAnnotationInterceptorTest {

    private OakdomXssAnnotationInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        interceptor = new OakdomXssAnnotationInterceptor();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    // -------------------------------------------------------------------------
    // Non-HandlerMethod handler
    // -------------------------------------------------------------------------

    @Test
    void nonHandlerMethodReturnsTrue() throws Exception {
        assertTrue(interceptor.preHandle(request, response, "not-a-handler-method"));
        assertNull(request.getAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL));
    }

    // -------------------------------------------------------------------------
    // Method-level @OakdomXssExclude
    // -------------------------------------------------------------------------

    @Test
    void methodExcludeAnnotationSetsExcludeAllAttribute() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "excludedMethod");
        assertTrue(interceptor.preHandle(request, response, handler));
        assertEquals(Boolean.TRUE, request.getAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL));
    }

    @Test
    void methodExcludeAnnotationSkipsParameterProcessing() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "excludedMethod");
        interceptor.preHandle(request, response, handler);
        assertNull(request.getAttribute(OakdomXssRequestAttributes.METHOD_MODE));
    }

    // -------------------------------------------------------------------------
    // Method-level @OakdomXssFilterMode
    // -------------------------------------------------------------------------

    @Test
    void methodFilterModeAnnotationSetsMethodModeAttribute() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "whitelistMethod", String.class);
        interceptor.preHandle(request, response, handler);
        assertEquals(FilterMode.WHITELIST, request.getAttribute(OakdomXssRequestAttributes.METHOD_MODE));
    }

    // -------------------------------------------------------------------------
    // Parameter-level @OakdomXssExclude on @RequestParam
    // -------------------------------------------------------------------------

    @Test
    void requestParamExcludeAnnotationSetsParamExcludeAttribute() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "excludedParamMethod",
                String.class, String.class);
        interceptor.preHandle(request, response, handler);
        assertEquals(Boolean.TRUE,
                request.getAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "rawContent"));
        assertNull(request.getAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "title"));
    }

    // -------------------------------------------------------------------------
    // Parameter-level @OakdomXssFilterMode on @RequestParam
    // -------------------------------------------------------------------------

    @Test
    void requestParamFilterModeAnnotationSetsParamModeAttribute() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "paramModeMethod",
                String.class, String.class);
        interceptor.preHandle(request, response, handler);
        assertEquals(FilterMode.WHITELIST,
                request.getAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "content"));
        assertNull(request.getAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "title"));
    }

    // -------------------------------------------------------------------------
    // Parameter-level @OakdomXssExclude on @RequestBody
    // -------------------------------------------------------------------------

    @Test
    void requestBodyExcludeAnnotationSetsBodyExcludeAttribute() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "excludedBodyMethod", String.class);
        interceptor.preHandle(request, response, handler);
        assertEquals(Boolean.TRUE, request.getAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE));
    }

    // -------------------------------------------------------------------------
    // Parameter-level @OakdomXssFilterMode on @RequestBody
    // -------------------------------------------------------------------------

    @Test
    void requestBodyFilterModeAnnotationSetsBodyModeAttribute() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "bodyModeMethod", String.class);
        interceptor.preHandle(request, response, handler);
        assertEquals(FilterMode.WHITELIST, request.getAttribute(OakdomXssRequestAttributes.BODY_MODE));
    }

    // -------------------------------------------------------------------------
    // No annotation — no attributes set
    // -------------------------------------------------------------------------

    @Test
    void noAnnotationSetsNoAttributes() throws Exception {
        HandlerMethod handler = handlerMethod(AnnotatedController.class, "plainMethod", String.class);
        interceptor.preHandle(request, response, handler);
        assertNull(request.getAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL));
        assertNull(request.getAttribute(OakdomXssRequestAttributes.METHOD_MODE));
        assertNull(request.getAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE));
        assertNull(request.getAttribute(OakdomXssRequestAttributes.BODY_MODE));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private HandlerMethod handlerMethod(Class<?> clazz, String methodName, Class<?>... paramTypes)
            throws NoSuchMethodException {
        Object bean = new AnnotatedController();
        Method method = clazz.getDeclaredMethod(methodName, paramTypes);
        return new HandlerMethod(bean, method);
    }

    // -------------------------------------------------------------------------
    // Fake controller for annotation resolution
    // -------------------------------------------------------------------------

    @SuppressWarnings("unused")
    static class AnnotatedController {

        @OakdomXssExclude
        public void excludedMethod() {}

        @OakdomXssFilterMode(FilterMode.WHITELIST)
        public void whitelistMethod(@RequestParam String title) {}

        public void excludedParamMethod(
                @RequestParam String title,
                @OakdomXssExclude @RequestParam("rawContent") String rawContent) {}

        public void paramModeMethod(
                @RequestParam String title,
                @OakdomXssFilterMode(FilterMode.WHITELIST) @RequestParam String content) {}

        public void excludedBodyMethod(@OakdomXssExclude @RequestBody String body) {}

        public void bodyModeMethod(@OakdomXssFilterMode(FilterMode.WHITELIST) @RequestBody String body) {}

        public void plainMethod(@RequestParam String name) {}
    }
}
