package io.sloptropy.ghidra.mcp.api;

import ghidra.program.model.listing.Program;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Shared infrastructure for mutating tools: EDT hop + transaction
 * discipline, exactly as the §4 rename_symbol / set_comment specs
 * prescribe.
 *
 * Mutating tools build a small lambda that performs the actual mutation
 * (a {@link MutationBody}) and call {@link #run(Program, String, MutationBody)}.
 * The helper:
 *   1. Dispatches onto the Swing event-dispatch thread (or runs directly
 *      if already on EDT).
 *   2. Opens a Ghidra transaction with the supplied name (shown in the
 *      undo menu).
 *   3. Invokes the body; collects its return value or thrown exception.
 *   4. Commits on success, aborts on any throwable.
 *   5. Returns the body's value (success) or rethrows the caught
 *      exception (failure) on the caller's thread.
 *
 * Body semantics:
 *   - Returning the sentinel object {@link #SKIP_TRANSACTION} signals
 *     "no work needed; do not commit a transaction." Used by set_comment's
 *     no-op-clear path to avoid polluting Ghidra's undo stack.
 *   - Any other return value is the tool's result and is returned to
 *     the caller.
 *   - Throwing anything aborts the transaction and propagates the
 *     throwable through {@link MutationException}.
 */
public final class Mutation {

    /** Sentinel: body completed but no transaction should be committed. */
    public static final Object SKIP_TRANSACTION = new Object();

    private Mutation() {}

    @FunctionalInterface
    public interface MutationBody {
        /**
         * Perform the mutation. Runs ON the EDT. May throw any Throwable;
         * the helper will abort the transaction and rethrow.
         *
         * @return the tool's result value, or {@link #SKIP_TRANSACTION}
         *         to indicate the call was a no-op and the transaction
         *         should not be committed.
         */
        Object call() throws Throwable;
    }

    public static Object run(Program program, String txName, MutationBody body)
            throws MutationException {
        AtomicReference<Object> resultRef = new AtomicReference<>();
        AtomicReference<Throwable> errorRef = new AtomicReference<>();

        Runnable r = () -> {
            // Probe the body once with no transaction so it can signal
            // SKIP_TRANSACTION. The body must be cheap on the skip path
            // (read-only). A body that wants to skip MUST decide that
            // BEFORE doing any mutating work.
            //
            // Pattern: the body's first move is a state inspection. If
            // the desired end-state is already present, return SKIP.
            // Otherwise, the helper opens the transaction and re-invokes.
            //
            // We implement "single invocation + transaction-by-default"
            // here: the body is invoked once, inside the transaction. If
            // it returns SKIP_TRANSACTION, we abort (don't commit) so
            // the transaction never lands in the undo stack. Ghidra's
            // endTransaction(commit=false) is idempotent w.r.t. an
            // un-mutated transaction.
            int tx = program.startTransaction(txName);
            boolean commit = false;
            try {
                Object result = body.call();
                if (result == SKIP_TRANSACTION) {
                    commit = false; // abort the empty transaction
                } else {
                    commit = true;
                    resultRef.set(result);
                }
            } catch (Throwable t) {
                errorRef.set(t);
                commit = false;
            } finally {
                try {
                    program.endTransaction(tx, commit);
                } catch (Throwable t) {
                    // If endTransaction itself fails AND we had no prior
                    // error, surface this one. Otherwise the prior error
                    // is the more interesting signal.
                    if (errorRef.get() == null) errorRef.set(t);
                }
            }
        };

        try {
            if (SwingUtilities.isEventDispatchThread()) {
                r.run();
            } else {
                SwingUtilities.invokeAndWait(r);
            }
        } catch (InvocationTargetException e) {
            throw new MutationException(e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MutationException(e);
        }

        Throwable err = errorRef.get();
        if (err != null) {
            throw new MutationException(err);
        }
        return resultRef.get(); // null iff body returned SKIP_TRANSACTION
    }

    /** Wraps any throwable raised inside the mutation body. */
    public static final class MutationException extends Exception {
        public MutationException(Throwable cause) { super(cause); }
    }
}
