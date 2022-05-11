package org.opensearch.security.tools;

import org.junit.Assert;
import org.junit.Test;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

public class CommandTests {
    class MockCommandImpl extends Command {
        @Override
        public int execute(final String[] args) throws Exception {
            if(args[0].equals("success"))
                return 0;
            return 1;
        }

        public String describe() { return "testDescribe"; }

        public void usage() { }

        @Override
        public void exit(int status) {
            if(status != 0) System.out.println("failure");
            else System.out.println("success");
        }
    }

    @Test
    public void testMain() {
        final ByteArrayOutputStream outputStreamCaptor = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStreamCaptor));

        String args[] = {"success"};
        MockCommandImpl mockCommand = new MockCommandImpl();

        try { mockCommand.main(args); } catch (Exception e) { }
        Assert.assertEquals("success", outputStreamCaptor.toString()
                .trim());

        outputStreamCaptor.reset();

        String args2[] = {"failure"};
        try { mockCommand.main(args2); } catch(Exception e) { }
        Assert.assertEquals("failure", outputStreamCaptor.toString()
                .trim());
    }
}
