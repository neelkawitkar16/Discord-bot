from email import message
import discord
import re, json
from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError

Discord_TOKEN = 'Mdfgdfg564564646#################################'

client = discord.Client()

@client.event
async def on_ready():
  print('Bot is now online and ready to roll')


def getMessageBody(ip, context):
  return f"""
  IP: {ip}
  Last Analyzed stats:
    Harmless: {context["data"]["attributes"]["last_analysis_stats"]["harmless"]}
  """

@client.event
async def on_message(message):

    if message.author == client.user:
      return

# Check if the message contains IP address
    streamables = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
    match = streamables.search(message.content)
    if match and message.channel.id == 4645643453535353535353535353535353535353535353535353511:
        ip = match.group()
        print(ip)
        # await message.channel.send(ip)

# Provide contextual information regarding IP addresses
        vt_api_ip_addresses = VirusTotalAPIIPAddresses('1e@@##$$#sdgfdgdfh675757fsdfsfsfs##$$$8185')
        try:
            result = vt_api_ip_addresses.get_report(ip)
        except VirusTotalAPIError as err:
            print(err, err.err_code)
        else:
            if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
                result = json.loads(result)
                await message.channel.send(getMessageBody(ip, result))
                result = json.dumps(result, sort_keys=False, indent=4)
                print(result)
            else:
                print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')

client.run(Discord_TOKEN)

print("Android")
