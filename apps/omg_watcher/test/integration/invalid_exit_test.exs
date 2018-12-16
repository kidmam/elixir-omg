# Copyright 2018 OmiseGO Pte Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule OMG.Watcher.Integration.InvalidExitTest do
  use ExUnitFixtures
  use ExUnit.Case, async: false
  use OMG.API.Fixtures
  use OMG.API.Integration.Fixtures
  use Plug.Test
  use Phoenix.ChannelTest

  alias OMG.API
  alias OMG.API.Utxo
  require Utxo
  alias OMG.Eth
  alias OMG.RPC.Client
  alias OMG.Watcher.Eventer.Event
  alias OMG.Watcher.Integration.TestHelper, as: IntegrationTest
  alias OMG.Watcher.Web.Channel
  alias OMG.Watcher.Web.Serializers.Response

  import ExUnit.CaptureLog

  @moduletag :integration

  @timeout 40_000
  @eth API.Crypto.zero_address()

  @endpoint OMG.Watcher.Web.Endpoint

  @tag fixtures: [:watcher_sandbox, :stable_alice, :child_chain, :token, :stable_alice_deposits]
  test "exit which is using already spent utxo from transaction causes to emit invalid_exit event", %{
    stable_alice: alice,
    stable_alice_deposits: {deposit_blknum, _}
  } do
    {:ok, _, event_socket} = subscribe_and_join(socket(), Channel.Byzantine, "byzantine")

    tx = API.TestHelper.create_encoded([{deposit_blknum, 0, 0, alice}], @eth, [{alice, 10}])
    {:ok, %{blknum: deposit_blknum}} = Client.submit(tx)

    tx = API.TestHelper.create_encoded([{deposit_blknum, 0, 0, alice}], @eth, [{alice, 10}])
    {:ok, %{blknum: tx_blknum, tx_hash: _tx_hash}} = Client.submit(tx)

    IntegrationTest.wait_for_block_fetch(tx_blknum, @timeout)

    %{
      "txbytes" => txbytes,
      "proof" => proof,
      "sigs" => sigs,
      "utxo_pos" => utxo_pos
    } = IntegrationTest.get_exit_data(deposit_blknum, 0, 0)

    {:ok, %{"status" => "0x1", "blockNumber" => eth_height}} =
      Eth.RootChain.start_exit(
        utxo_pos,
        txbytes,
        proof,
        sigs,
        alice.addr
      )
      |> Eth.DevHelpers.transact_sync!()

    invalid_exit_event =
      %Event.InvalidExit{
        amount: 10,
        currency: @eth,
        owner: alice.addr,
        utxo_pos: utxo_pos,
        eth_height: eth_height
      }
      |> Response.clean_artifacts()

    IntegrationTest.wait_for_exit_processing(eth_height, @timeout)
    assert_push("invalid_exit", ^invalid_exit_event)

    # after the notification has been received, a challenged is composed and sent
    challenge = IntegrationTest.get_exit_challenge(deposit_blknum, 0, 0)
    assert {:ok, {alice.addr, @eth, 10}} == Eth.RootChain.get_exit(utxo_pos)

    {:ok, %{"status" => "0x1"}} =
      OMG.Eth.RootChain.challenge_exit(
        challenge["cutxopos"],
        challenge["eutxoindex"],
        challenge["txbytes"],
        challenge["proof"],
        challenge["sigs"],
        alice.addr
      )
      |> Eth.DevHelpers.transact_sync!()

    assert {:ok, {API.Crypto.zero_address(), @eth, 10}} == Eth.RootChain.get_exit(utxo_pos)

    Process.sleep(5_000)

    # re subscribe fresh, so we don't get old events in the socket
    Process.unlink(event_socket.channel_pid)
    :ok = close(event_socket)
    clear_mailbox()

    {:ok, _, _socket} = subscribe_and_join(socket(), Channel.Byzantine, "byzantine")

    # no more pestering the user, the invalid exit is gone
    refute_push("invalid_exit", _, 2_000)
  end

  # clears the mailbox of `self()`. Useful to purge old events that shouldn't be emitted anymore after some action
  defp clear_mailbox do
    receive do
      _ -> clear_mailbox()
    after
      0 -> :ok
    end
  end

  @tag fixtures: [:watcher_sandbox, :stable_alice, :child_chain, :token, :stable_alice_deposits, :test_server]
  test "transaction which is using already spent utxo from exit and happened before end of margin of slow validator (m_sv) causes to emit invalid_exit event ",
       %{stable_alice: alice, stable_alice_deposits: {deposit_blknum, _}, test_server: context} do
    tx = API.TestHelper.create_encoded([{deposit_blknum, 0, 0, alice}], @eth, [{alice, 10}])
    {:ok, %{blknum: exit_blknum}} = Client.submit(tx)

    # Here we're preparing invalid block
    bad_block_number = 2_000
    bad_tx = API.TestHelper.create_recovered([{exit_blknum, 0, 0, alice}], @eth, [{alice, 10}])

    %{hash: bad_block_hash, number: _, transactions: _} =
      bad_block = API.Block.hashed_txs_at([bad_tx], bad_block_number)

    # from now on the child chain server is broken until end of test
    OMG.Watcher.Integration.BadChildChainServer.prepare_route_to_inject_bad_block(context, bad_block, bad_block_hash)

    {:ok, _, _socket} = subscribe_and_join(socket(), Channel.Byzantine, "byzantine")

    IntegrationTest.wait_for_block_fetch(exit_blknum, @timeout)

    %{
      "txbytes" => txbytes,
      "proof" => proof,
      "sigs" => sigs,
      "utxo_pos" => utxo_pos
    } = IntegrationTest.get_exit_data(exit_blknum, 0, 0)

    {:ok, %{"status" => "0x1", "blockNumber" => eth_height}} =
      Eth.RootChain.start_exit(
        utxo_pos,
        txbytes,
        proof,
        sigs,
        alice.addr
      )
      |> Eth.DevHelpers.transact_sync!()

    # Here we're manually submitting invalid block to the root chain
    {:ok, _} = OMG.Eth.RootChain.submit_block(bad_block_hash, 2, 1)

    IntegrationTest.wait_for_block_fetch(bad_block_number, @timeout)

    invalid_exit_event =
      %Event.InvalidExit{
        amount: 10,
        currency: @eth,
        owner: alice.addr,
        utxo_pos: utxo_pos,
        eth_height: eth_height
      }
      |> Response.clean_artifacts()

    IntegrationTest.wait_for_exit_processing(eth_height, @timeout)
    assert_push("invalid_exit", ^invalid_exit_event)
  end

  @tag fixtures: [:watcher_sandbox, :stable_alice, :child_chain, :token, :stable_alice_deposits]
  test "invalid exit is detected after block withholding", %{
    stable_alice: alice,
    stable_alice_deposits: {deposit_blknum, _}
  } do
    {:ok, _, _socket} = subscribe_and_join(socket(), Channel.Byzantine, "byzantine")

    tx = API.TestHelper.create_encoded([{deposit_blknum, 0, 0, alice}], @eth, [{alice, 10}])
    {:ok, %{blknum: deposit_blknum}} = Client.submit(tx)

    tx = API.TestHelper.create_encoded([{deposit_blknum, 0, 0, alice}], @eth, [{alice, 10}])
    {:ok, %{blknum: tx_blknum, tx_hash: _tx_hash}} = Client.submit(tx)

    IntegrationTest.wait_for_block_fetch(tx_blknum, @timeout)

    {next_blknum, nonce} = get_next_blknum_nonce(tx_blknum)

    assert capture_log(fn ->
             {:ok, _txhash} = Eth.RootChain.submit_block(<<0::256>>, nonce, 20_000_000_000)

             IntegrationTest.assert_block_getter_down()
           end) =~ inspect(:withholding)

    block_withholding_event =
      %Event.BlockWithholding{
        blknum: next_blknum
      }
      |> Response.clean_artifacts()

    assert_push("block_withholding", ^block_withholding_event)

    %{
      "txbytes" => txbytes,
      "proof" => proof,
      "sigs" => sigs,
      "utxo_pos" => utxo_pos
    } = IntegrationTest.get_exit_data(deposit_blknum, 0, 0)

    {:ok, %{"status" => "0x1", "blockNumber" => eth_height}} =
      Eth.RootChain.start_exit(
        utxo_pos,
        txbytes,
        proof,
        sigs,
        alice.addr
      )
      |> Eth.DevHelpers.transact_sync!()

    invalid_exit_event =
      %Event.InvalidExit{
        amount: 10,
        currency: @eth,
        owner: alice.addr,
        utxo_pos: utxo_pos,
        eth_height: eth_height
      }
      |> Response.clean_artifacts()

    exit_processor_validation = Application.fetch_env!(:omg_watcher, :exit_processor_validation_interval_ms)
    assert_push("invalid_exit", ^invalid_exit_event, exit_processor_validation + 10_000)
  end

  defp get_next_blknum_nonce(blknum) do
    next_blknum = blknum + 1000
    {next_blknum, trunc(next_blknum / 1000)}
  end
end
