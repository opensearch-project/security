package org.opensearch.security.tools;

public abstract class Command {
    public abstract int execute(final String[] args) throws Exception;

    public abstract String describe();

    public abstract void usage();

    public void exit(int status) {
        System.exit(status);
    }

    public void main(final String[] args) throws Exception {
        try{
            final int returnCode = execute(args);
            exit(returnCode);
        } catch (Throwable e) {
            System.out.println(String.format("Unexpected error: %s. See stack trace below\n %s",
                    e.getMessage(), e.getStackTrace()));
            exit(-1);
        }
    }
}
