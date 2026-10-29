package com.algorand.algosdk.unit;

import java.io.File;
import java.security.NoSuchAlgorithmException;

import com.algorand.algosdk.crypto.Address;
import com.algorand.algosdk.unit.utils.ClientMocker;
import com.algorand.algosdk.unit.utils.TestingUtils;
import com.algorand.algosdk.v2.client.common.AlgodClient;
import com.algorand.algosdk.v2.client.common.Response;
import com.algorand.algosdk.v2.client.model.BlockResponse;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The SDK-side half of the section 8 Java fixtures: removable glue for the
 * operator gate to install into a provisioned, re-stripped Algorand workspace
 * beside fixture.feature and run once through the harness.  Nothing in the
 * repository runs it on its own.  What each step exists to show, by the tuple
 * it must leave:
 *
 * <ul>
 * <li>{@code AlgodClient.<init>} from THIS file: a glue field initialiser is a
 *     direct call of the glue (2.4);</li>
 * <li>{@code Encoder.decodeFromBase64} with caller
 *     {@code src/test/java/com/algorand/algosdk/unit/utils/ClientMocker.java}:
 *     the retained helper's production call is recorded and is not direct;</li>
 * <li>{@code Address.<init>} from a Mockito answer registered here: reached
 *     through Mockito's frames, caller_file null, not direct -- the shape the
 *     retained ClientMocker's own answer would have if it called production;</li>
 * <li>the same {@code Address.<init>} called from the step body: caller this file;</li>
 * <li>production methods {@code TestingUtils.verifyResponse} calls
 *     ({@code Response.isSuccessful} and friends) with caller
 *     {@code .../unit/utils/TestingUtils.java}: retained, not direct.</li>
 * </ul>
 *
 * <p>And what each step's TAG must be (TARGET_INTERFACES_V2_SPEC section 4).
 * The scenario's steps are Given, When, Then, so the indices are 0, 1, 2 --
 * the same order {@code records_from_json} writes the record's {@code steps}
 * in.  {@code Address.<init>} is called from three places on purpose:
 *
 * <ul>
 * <li>the {@code @Before} hook: {@code step} null, because a hook is not a
 *     step and must never be charged to the step before or after it;</li>
 * <li>the Given step: {@code step} 0;</li>
 * <li>the Then step: {@code step} 2.</li>
 * </ul>
 *
 * <p>One tuple, three events: the step is part of an event's identity.  The
 * field initialiser's {@code AlgodClient.<init>} carries null as well -- the
 * glue is constructed before the first step starts.
 */
public class R2TDirectCallFixture {
    /** Field initialiser: javac compiles it into this class's constructor. */
    AlgodClient client = new AlgodClient("localhost", 123, "");

    Response<BlockResponse> response;
    Address fromHook;
    Address fromGiven;
    Address fromAnswer;
    Address fromStep;

    /** Not a step: its call must carry no step index at all. */
    @Before
    public void hook() throws NoSuchAlgorithmException {
        fromHook = new Address();
    }

    @Given("the fixture has an address")
    public void given() throws NoSuchAlgorithmException {
        fromGiven = new Address();
    }

    @When("the fixture fetches a mocked base64 block {string}")
    public void fetch(String bodyFile) throws Exception {
        ClientMocker.infect(client);
        // A `.base64` body makes ClientMocker.oneResponse call
        // Encoder.decodeFromBase64 from the retained helper.
        ClientMocker.oneResponse(200, "application/msgpack",
                                 new File("src/test/resources/" + bodyFile));
        response = client.GetBlock(1L).execute();
        TestingUtils.verifyResponse(response, new File("src/test/resources/" + bodyFile));
    }

    @Then("a Mockito answer constructs an address and so does the step")
    public void answers() throws Exception {
        Runnable mock = Mockito.mock(Runnable.class);
        Mockito.doAnswer(invocation -> {
            fromAnswer = new Address();
            return null;
        }).when(mock).run();
        mock.run();
        fromStep = new Address();
        assertThat(fromAnswer).isNotNull();
        assertThat(fromStep).isEqualTo(fromAnswer);
    }
}
