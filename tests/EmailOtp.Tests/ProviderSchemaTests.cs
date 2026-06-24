using EmailOtp;
using EmailOtp.EntityFramework;
using EmailOtp.Tests.Fakes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace EmailOtp.Tests;

/// <summary>
/// Verifies the schema EF generates per provider — specifically that the single-active-slot guarantee
/// materializes as a <b>filtered unique index</b> on both SQLite and SQL Server. These use offline
/// model-to-DDL generation (no live database).
/// </summary>
public class ProviderSchemaTests
{
    [Fact]
    public void Active_status_must_stay_zero_to_match_the_filtered_index()
    {
        // The filtered unique index is "WHERE [Status] = 0". If the enum order changes so that Active is
        // no longer 0, the index would filter on the wrong status and the single-active guarantee breaks.
        Assert.Equal(0, (int)EmailOtpChallengeStatus.Active);
    }

    [Fact]
    public void Sqlite_emits_filtered_unique_index()
    {
        using var conn = new SqliteConnection("DataSource=:memory:");
        conn.Open();
        var options = new DbContextOptionsBuilder<TestEmailOtpDbContext>().UseSqlite(conn).Options;
        using var ctx = new TestEmailOtpDbContext(options);

        var ddl = ctx.Database.GenerateCreateScript();

        Assert.Contains("CREATE UNIQUE INDEX", ddl, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"Email\", \"Purpose\"", ddl);
        Assert.Contains("WHERE [Status] = 0", ddl);
    }

    [Fact]
    public void SqlServer_emits_filtered_unique_index()
    {
        // GenerateCreateScript builds DDL from the model offline; no connection is opened.
        var options = new DbContextOptionsBuilder<TestEmailOtpDbContext>()
            .UseSqlServer("Server=localhost;Database=none;Trusted_Connection=True;")
            .Options;
        using var ctx = new TestEmailOtpDbContext(options);

        var ddl = ctx.Database.GenerateCreateScript();

        Assert.Contains("CREATE UNIQUE INDEX", ddl, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[Email], [Purpose]", ddl);
        Assert.Contains("WHERE [Status] = 0", ddl);
    }
}
