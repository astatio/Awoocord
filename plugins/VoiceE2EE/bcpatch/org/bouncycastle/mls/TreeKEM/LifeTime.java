/*
 * From BouncyCastle bcmls 1.86 (MIT licence, see ../../../../BOUNCYCASTLE-LICENSE.md), changed for VoiceE2EE:
 * verify() used java.time, which Android only has from API 26; it now uses System.currentTimeMillis().
 * Everything else is unchanged. (DAVE members don't rely on key package lifetimes anyway.)
 */
package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

public class LifeTime
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    private final long not_before;
    private final long not_after;

    @SuppressWarnings("unused")
    public LifeTime(MLSInputStream stream)
        throws IOException
    {
        not_before = (long)stream.read(long.class);
        not_after = (long)stream.read(long.class);
    }

    public LifeTime()
    {
        // not_before = 0, not_after = 2^64 - 1: the lifetime the Discord voice gateway requires
        this.not_before = 0;
        this.not_after = -1;
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(not_before);
        stream.write(not_after);
    }

    protected boolean verify()
    {
        long now = System.currentTimeMillis() / 1000L;
        if (not_after == -1)
        {
            return (now >= not_before) && (now < Long.MAX_VALUE);
        }
        return (now >= not_before) && (now < not_after);
    }
}
