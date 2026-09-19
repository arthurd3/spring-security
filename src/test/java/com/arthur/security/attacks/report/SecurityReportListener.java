package com.arthur.security.attacks.report;

import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestPlan;

/**
 * Prints the {@link SecurityReport} summary table once the whole test plan has finished.
 *
 * <p>Registered through {@code META-INF/services/org.junit.platform.launcher.TestExecutionListener},
 * which Surefire picks up via the ServiceLoader. This callback runs while Surefire is still draining
 * the forked JVM's stdout - a JVM shutdown hook fires too late and its output is discarded.
 */
public class SecurityReportListener implements TestExecutionListener {

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        SecurityReport.printSummary();
    }
}
