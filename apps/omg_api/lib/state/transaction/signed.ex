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

defmodule OMG.API.State.Transaction.Signed do
  @moduledoc """
  Representation of a signed transaction
  """

  alias OMG.API.Crypto
  alias OMG.API.State.Transaction

  @signature_length 65
  @type signed_tx_bytes_t() :: bitstring() | nil

  defstruct [:raw_tx, :sigs, :signed_tx_bytes]

  @type t() :: %__MODULE__{
          raw_tx: Transaction.t(),
          sigs: [Crypto.sig_t()],
          signed_tx_bytes: signed_tx_bytes_t()
        }

  def signed_hash(%__MODULE__{raw_tx: tx, sigs: sigs}) do
    tx_hash = Transaction.hash(tx)
    hash_with_sigs = Enum.reduce(sigs, tx_hash, fn sig, hash -> hash <> sig end)
    Crypto.hash(hash_with_sigs)
  end

  def encode(%__MODULE__{
        raw_tx: %Transaction{inputs: [input1, input2], outputs: [output1, output2]},
        sigs: [sig1, sig2]
      }) do
    [
      input1.blknum,
      input1.txindex,
      input1.oindex,
      input2.blknum,
      input2.txindex,
      input2.oindex,
      output1.currency,
      output1.owner,
      output1.amount,
      output2.owner,
      output2.amount,
      sig1,
      sig2
    ]
    |> ExRLP.encode()
  end

  def decode(signed_tx_bytes) do
    with {:ok, %Transaction{} = tx, [sig1, sig2] = sigs} <- Transaction.decode(signed_tx_bytes),
         :ok <- signature_length?(sig1),
         :ok <- signature_length?(sig2) do
      {:ok,
       %__MODULE__{
         raw_tx: tx,
         sigs: sigs,
         signed_tx_bytes: signed_tx_bytes
       }}
    else
      {:ok, %Transaction{}, _} -> {:error, :malformed_signed_transaction}
      error -> error
    end
  end

  defp signature_length?(sig) when byte_size(sig) == @signature_length, do: :ok
  defp signature_length?(_sig), do: {:error, :bad_signature_length}
end
