<template>
	<v-row>
		<v-col v-for="(m, i) in missions" :key="i">
			<v-card
				v-bind:title="m.name"
			>
				<template v-slot:title>
				<img v-bind:src="'/imgs/'+m.name+'.png'"></img>
				</template>
				<v-card-text class="bg-surface-light pt-4">
				{{m.text}}
				</v-card-text>
				<v-card-actions>
					
					<v-btn><router-link :to="{name: '/MissionLogin', query: {mission: m.name}}">More Details</router-link></v-btn>
				</v-card-actions>
			</v-card>
		</v-col>
		<v-col>
			<v-card title="New Mission" text="Create a new mission">
				<v-card-actions>
					<v-btn><router-link :to="{name: '/MissionCreate'}">+</router-link></v-btn>
				</v-card-actions>
			</v-card>
		</v-col>
	</v-row>
</template>

<script>
export default {
	data: () => ({
		missions: [
		]
	}),
	mounted () {
		fetch('/api/missions')
		  .then(response => (response.json().then(
		  	(data) => this.missions = data
		  )))
	  }
}
</script>
