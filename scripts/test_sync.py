import vulnkit

vulnkit.config.load({
    "sources": ["redhat", "nvd"],
})
conf = vulnkit.config.get()
print(conf)

vulnkit.config.load()
conf = vulnkit.config.get()
print(conf)
