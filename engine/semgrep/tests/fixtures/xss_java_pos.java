import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class xss_java_pos extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("input");
        PrintWriter out = response.getWriter();

        // unencoded request data straight into the response body
        out.println(param);
        response.getWriter().write("<div>" + request.getHeader("X-Name") + "</div>");
    }
}
